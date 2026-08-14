"""Android binary XML (AXML) parser.

Parses the binary AndroidManifest.xml found inside APK/AAB archives.
Plain-text XML is also accepted for fixtures and non-standard packages.
"""

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

ANDROID_NS = "http://schemas.android.com/apk/res/android"

RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

UTF8_FLAG = 1 << 8
NO_ENTRY = 0xFFFFFFFF

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

ANDROID_ATTR_IDS: dict[int, str] = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010006: "permission",
    0x01010007: "readPermission",
    0x01010008: "writePermission",
    0x01010009: "protectionLevel",
    0x0101000B: "sharedUserId",
    0x0101000E: "enabled",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010011: "process",
    0x01010018: "authorities",
    0x0101001B: "grantUriPermissions",
    0x0101001C: "priority",
    0x0101002D: "allowBackup",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x010102D3: "hardwareAccelerated",
    0x010103A7: "required",
    0x010104EA: "extractNativeLibs",
    0x010104EB: "fullBackupContent",
    0x010104EC: "usesCleartextTraffic",
    0x01010527: "networkSecurityConfig",
    0x01010572: "compileSdkVersion",
    0x01010573: "compileSdkVersionCodename",
}


class AxmlError(ValueError):
    """Raised when binary XML cannot be parsed."""


@dataclass
class AxmlAttribute:
    name: str
    namespace: str | None
    value: Any
    raw: str | None
    resource_id: int | None = None
    data_type: int | None = None


@dataclass
class AxmlNode:
    name: str
    namespace: str | None
    attributes: dict[str, AxmlAttribute] = field(default_factory=dict)
    children: list[AxmlNode] = field(default_factory=list)
    text: str | None = None

    def attr(self, name: str, default: Any = None) -> Any:
        if name in self.attributes:
            return self.attributes[name].value
        android_name = f"{{{ANDROID_NS}}}{name}"
        if android_name in self.attributes:
            return self.attributes[android_name].value
        short = name.split("}")[-1]
        for key, attr in self.attributes.items():
            if key == short or key.endswith("}" + short) or attr.name == short:
                return attr.value
        return default

    def findall(self, name: str) -> list[AxmlNode]:
        return [child for child in self.children if child.name == name or child.name.endswith("}" + name)]

    def iter(self) -> list[AxmlNode]:
        nodes = [self]
        for child in self.children:
            nodes.extend(child.iter())
        return nodes


def is_binary_xml(data: bytes) -> bool:
    if len(data) < 8:
        return False
    chunk_type = struct.unpack_from("<H", data, 0)[0]
    return chunk_type in {RES_XML_TYPE, RES_STRING_POOL_TYPE}


def is_text_xml(data: bytes) -> bool:
    stripped = data.lstrip()
    return stripped.startswith(b"<") or stripped.startswith(b"\xef\xbb\xbf<")


def parse_manifest_bytes(data: bytes) -> AxmlNode:
    if is_text_xml(data):
        return parse_text_xml(data)
    if is_binary_xml(data):
        return parse_axml(data)
    raise AxmlError("AndroidManifest.xml is neither binary AXML nor text XML")


def parse_text_xml(data: bytes) -> AxmlNode:
    try:
        root = ET.fromstring(data.decode("utf-8"))
    except (UnicodeDecodeError, ET.ParseError) as exc:
        raise AxmlError(f"Invalid text XML: {exc}") from exc
    return _element_to_node(root)


def _element_to_node(element: ET.Element) -> AxmlNode:
    name = element.tag.split("}")[-1]
    namespace = None
    if element.tag.startswith("{") and "}" in element.tag:
        namespace = element.tag[1 : element.tag.index("}")]
    attrs: dict[str, AxmlAttribute] = {}
    for key, value in element.attrib.items():
        attr_name = key.split("}")[-1]
        attr_ns = None
        if key.startswith("{") and "}" in key:
            attr_ns = key[1 : key.index("}")]
        coerced = _coerce_text_value(value)
        attrs[key] = AxmlAttribute(
            name=attr_name,
            namespace=attr_ns,
            value=coerced,
            raw=value,
        )
    node = AxmlNode(name=name, namespace=namespace, attributes=attrs, text=element.text)
    for child in list(element):
        node.children.append(_element_to_node(child))
    return node


def _coerce_text_value(value: str) -> Any:
    lowered = value.strip().lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if value.strip().isdigit() or (value.startswith("-") and value[1:].isdigit()):
        try:
            return int(value)
        except ValueError:
            return value
    return value


def parse_axml(data: bytes) -> AxmlNode:
    if len(data) < 8:
        raise AxmlError("AXML too small")
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != RES_XML_TYPE:
        # Some files start directly with a string pool.
        offset = 0
    else:
        if header_size < 8 or chunk_size > len(data):
            raise AxmlError("Invalid AXML header")
        offset = header_size

    strings: list[str] = []
    resource_ids: list[int] = []
    namespaces: dict[str, str] = {}
    stack: list[AxmlNode] = []
    root: AxmlNode | None = None

    while offset + 8 <= len(data):
        ctype, hsize, csize = struct.unpack_from("<HHI", data, offset)
        if csize < 8 or offset + csize > len(data):
            break
        payload = data[offset : offset + csize]
        if ctype == RES_STRING_POOL_TYPE:
            strings = _parse_string_pool(payload)
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            resource_ids = _parse_resource_map(payload, hsize)
        elif ctype == RES_XML_START_NAMESPACE_TYPE:
            prefix, uri = _parse_namespace(payload, strings)
            if uri:
                namespaces[uri] = prefix
        elif ctype == RES_XML_END_NAMESPACE_TYPE:
            prefix, uri = _parse_namespace(payload, strings)
            namespaces.pop(uri, None)
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            node = _parse_start_element(payload, strings, resource_ids)
            if stack:
                stack[-1].children.append(node)
            else:
                root = node
            stack.append(node)
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            if stack:
                stack.pop()
        elif ctype == RES_XML_CDATA_TYPE:
            if stack:
                stack[-1].text = _parse_cdata(payload, strings)
        offset += csize

    if root is None:
        raise AxmlError("AXML contained no root element")
    return root


def _parse_string_pool(chunk: bytes) -> list[str]:
    if len(chunk) < 28:
        raise AxmlError("String pool header too small")
    _type, header_size, size, string_count, style_count, flags, strings_start, _styles_start = (
        struct.unpack_from("<HHIIIIII", chunk, 0)
    )
    if string_count > 100_000:
        raise AxmlError("Unreasonable string pool size")
    offsets_start = header_size
    strings: list[str] = []
    utf8 = bool(flags & UTF8_FLAG)
    for index in range(string_count):
        off = offsets_start + index * 4
        if off + 4 > len(chunk):
            strings.append("")
            continue
        str_offset = struct.unpack_from("<I", chunk, off)[0]
        abs_off = strings_start + str_offset
        if abs_off >= len(chunk):
            strings.append("")
            continue
        if utf8:
            strings.append(_decode_utf8_string(chunk, abs_off))
        else:
            strings.append(_decode_utf16_string(chunk, abs_off))
    return strings


def _decode_length_utf16(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        return 0, offset
    value = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    if value & 0x8000:
        if offset + 2 > len(data):
            return 0, offset
        value = ((value & 0x7FFF) << 16) | struct.unpack_from("<H", data, offset)[0]
        offset += 2
    return value, offset


def _decode_length_utf8(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        return 0, offset
    value = data[offset]
    offset += 1
    if value & 0x80:
        if offset >= len(data):
            return 0, offset
        value = ((value & 0x7F) << 8) | data[offset]
        offset += 1
    return value, offset


def _decode_utf16_string(data: bytes, offset: int) -> str:
    length, pos = _decode_length_utf16(data, offset)
    end = pos + length * 2
    if end > len(data):
        end = len(data)
    try:
        return data[pos:end].decode("utf-16le", errors="replace")
    except Exception:
        return ""


def _decode_utf8_string(data: bytes, offset: int) -> str:
    _char_len, pos = _decode_length_utf8(data, offset)
    byte_len, pos = _decode_length_utf8(data, pos)
    end = pos + byte_len
    if end > len(data):
        end = len(data)
    try:
        return data[pos:end].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _parse_resource_map(chunk: bytes, header_size: int) -> list[int]:
    start = max(header_size, 8)
    ids: list[int] = []
    for offset in range(start, len(chunk) - 3, 4):
        ids.append(struct.unpack_from("<I", chunk, offset)[0])
    return ids


def _string_at(strings: list[str], index: int) -> str | None:
    if index == NO_ENTRY:
        return None
    if 0 <= index < len(strings):
        return strings[index]
    return None


def _parse_namespace(chunk: bytes, strings: list[str]) -> tuple[str | None, str | None]:
    if len(chunk) < 24:
        return None, None
    prefix_idx, uri_idx = struct.unpack_from("<II", chunk, 16)
    return _string_at(strings, prefix_idx), _string_at(strings, uri_idx)


def _parse_cdata(chunk: bytes, strings: list[str]) -> str | None:
    if len(chunk) < 28:
        return None
    idx = struct.unpack_from("<I", chunk, 16)[0]
    return _string_at(strings, idx)


def _parse_start_element(
    chunk: bytes,
    strings: list[str],
    resource_ids: list[int],
) -> AxmlNode:
    if len(chunk) < 36:
        raise AxmlError("Start element chunk too small")
    ns_idx, name_idx, attr_start, attr_size, attr_count, _id_idx, _class_idx, _style_idx = (
        struct.unpack_from("<IIHHHHHH", chunk, 16)
    )
    name = _string_at(strings, name_idx) or "unknown"
    namespace = _string_at(strings, ns_idx)
    node = AxmlNode(name=name, namespace=namespace)
    # attr_start is relative to the start of ResXMLTree_attrExt, which begins at offset 16.
    cursor = 16 + (attr_start or 20)
    size = attr_size or 20
    for _ in range(attr_count):
        if cursor + 20 > len(chunk):
            break
        ans_idx, aname_idx, raw_idx, value_size, _res0, data_type, data = struct.unpack_from(
            "<IIIHBBI", chunk, cursor
        )
        attr_ns = _string_at(strings, ans_idx)
        attr_name = _string_at(strings, aname_idx) or ""
        resource_id = None
        if 0 <= aname_idx < len(resource_ids):
            resource_id = resource_ids[aname_idx]
            if not attr_name and resource_id in ANDROID_ATTR_IDS:
                attr_name = ANDROID_ATTR_IDS[resource_id]
        elif resource_id is None and aname_idx < len(ANDROID_ATTR_IDS):
            pass
        raw = _string_at(strings, raw_idx)
        value = _decode_res_value(data_type, data, strings, raw)
        key = f"{{{attr_ns}}}{attr_name}" if attr_ns else attr_name
        node.attributes[key] = AxmlAttribute(
            name=attr_name,
            namespace=attr_ns,
            value=value,
            raw=raw,
            resource_id=resource_id,
            data_type=data_type,
        )
        _ = value_size
        cursor += size
    return node


def _decode_res_value(data_type: int, data: int, strings: list[str], raw: str | None) -> Any:
    if data_type == TYPE_STRING:
        return _string_at(strings, data) if data != NO_ENTRY else raw
    if data_type == TYPE_INT_BOOLEAN:
        return data != 0
    if data_type in {TYPE_INT_DEC, TYPE_INT_HEX}:
        return data
    if data_type == TYPE_REFERENCE:
        return f"@0x{data:08x}"
    if data_type == TYPE_ATTRIBUTE:
        return f"?0x{data:08x}"
    if data_type == TYPE_FLOAT:
        return struct.unpack("<f", struct.pack("<I", data))[0]
    if data_type == TYPE_NULL:
        return None
    return raw if raw is not None else data
