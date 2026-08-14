"""Android binary XML (AXML) encoder/decoder for AndroidManifest.xml.

The format matches the AOSP resource chunk layout. This module is used by the
custom manifest scanner; it does not invoke apktool or JADX.
"""

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any
from xml.etree.ElementTree import Element

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

UTF8_FLAG = 1 << 8

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_NS_PREFIX = "android"

# Common android: attribute resource IDs (framework-res). Used when the string
# pool name is empty but a resource map entry is present.
ANDROID_ATTR_BY_ID: dict[int, str] = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010006: "permission",
    0x0101000C: "enabled",
    0x0101000E: "multiprocess",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010011: "process",
    0x01010012: "taskAffinity",
    0x01010013: "permissionGroup",
    0x0101001A: "readPermission",
    0x0101001B: "writePermission",
    0x01010018: "authorities",
    0x0101001C: "grantUriPermissions",
    0x0101001D: "priority",
    0x0101001F: "screenOrientation",
    0x01010020: "configChanges",
    0x01010025: "protectionLevel",
    0x0101020C: "minSdkVersion",
    0x01010264: "targetSdkVersion",
    0x01010270: "targetSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010280: "allowBackup",
    0x010102D3: "fullBackupOnly",
    0x010103A7: "required",
    0x010103AA: "allowTaskReparenting",
    0x010104EC: "usesCleartextTraffic",
    0x01010527: "networkSecurityConfig",
    0x0101054D: "roundIcon",
    0x01010532: "appComponentFactory",
    0x0101000B: "maxSdkVersion",
    0x01010271: "maxSdkVersion",
    0x01010204: "targetActivity",
    0x0101001E: "launchMode",
    0x010102B4: "isolatedProcess",
    0x010103D0: "directBootAware",
    0x01010227: "scheme",
    0x01010026: "host",
    0x01010027: "path",
    0x0101002A: "port",
    0x0101002B: "pathPrefix",
    0x0101002C: "pathPattern",
    0x01010261: "mimeType",
}

ANDROID_ATTR_ID_BY_NAME: dict[str, int] = {name: rid for rid, name in ANDROID_ATTR_BY_ID.items()}
# Prefer the canonical targetSdkVersion id.
ANDROID_ATTR_ID_BY_NAME["targetSdkVersion"] = 0x01010270
ANDROID_ATTR_ID_BY_NAME["maxSdkVersion"] = 0x01010271

NO_INDEX = 0xFFFFFFFF


@dataclass
class XmlNode:
    name: str
    attributes: dict[str, str] = field(default_factory=dict)
    children: list[XmlNode] = field(default_factory=list)
    text: str | None = None

    def find(self, name: str) -> XmlNode | None:
        if self.name == name:
            return self
        for child in self.children:
            found = child.find(name)
            if found is not None:
                return found
        return None

    def findall(self, name: str) -> list[XmlNode]:
        matches: list[XmlNode] = []
        if self.name == name:
            matches.append(self)
        for child in self.children:
            matches.extend(child.findall(name))
        return matches

    def get(self, key: str, default: str | None = None) -> str | None:
        if key in self.attributes:
            return self.attributes[key]
        alt = key.split(":")[-1]
        for attr_key, value in self.attributes.items():
            if attr_key == alt or attr_key.endswith(":" + alt):
                return value
        return default


class AxmlError(ValueError):
    """Raised when binary XML cannot be parsed."""


def parse_manifest_bytes(data: bytes) -> XmlNode:
    """Parse AndroidManifest.xml bytes (binary AXML or plaintext XML)."""
    if not data:
        raise AxmlError("empty manifest")
    if data.lstrip().startswith(b"<") or data.lstrip().startswith(b"<?xml"):
        return _parse_plaintext_xml(data)
    try:
        return parse_axml(data)
    except AxmlError:
        # Some test fixtures / decoded dumps may still be XML with a BOM.
        try:
            return _parse_plaintext_xml(data)
        except Exception as exc:
            raise AxmlError("manifest is neither valid AXML nor XML") from exc


def parse_axml(data: bytes) -> XmlNode:
    if len(data) < 8:
        raise AxmlError("AXML too short")
    chunk_type, header_size, file_size = _chunk_header(data, 0)
    if chunk_type != RES_XML_TYPE:
        raise AxmlError(f"not an XML resource chunk: 0x{chunk_type:04x}")
    if file_size > len(data):
        file_size = len(data)

    strings: list[str] = []
    resource_ids: list[int] = []
    namespaces: dict[str, str] = {}  # uri -> prefix
    stack: list[XmlNode] = []
    root: XmlNode | None = None

    offset = header_size
    while offset + 8 <= file_size:
        ctype, cheader, csize = _chunk_header(data, offset)
        if csize < 8 or offset + csize > len(data):
            break
        if ctype == RES_STRING_POOL_TYPE:
            strings = _parse_string_pool(data, offset)
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            resource_ids = _parse_resource_map(data, offset, csize)
        elif ctype == RES_XML_START_NAMESPACE_TYPE:
            prefix = _string_at(strings, _u32(data, offset + 16))
            uri = _string_at(strings, _u32(data, offset + 20))
            if uri:
                namespaces[uri] = prefix or ANDROID_NS_PREFIX
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            node = _parse_start_element(data, offset, strings, resource_ids, namespaces)
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
                raw_idx = _u32(data, offset + 16)
                text = _string_at(strings, raw_idx)
                if text:
                    stack[-1].text = text
        offset += csize

    if root is None:
        raise AxmlError("AXML contained no elements")
    return root


def encode_axml(root: XmlNode) -> bytes:
    """Serialize an XmlNode tree to binary Android XML (UTF-16 string pool)."""
    attr_names: list[str] = []
    seen_attrs: set[str] = set()

    def collect_android_attrs(node: XmlNode) -> None:
        for key in node.attributes:
            local = _local_name(key)
            if key.startswith("android:") or local in ANDROID_ATTR_ID_BY_NAME:
                if local not in seen_attrs:
                    seen_attrs.add(local)
                    attr_names.append(local)
        for child in node.children:
            collect_android_attrs(child)

    collect_android_attrs(root)

    pool = _StringPool()
    for name in attr_names:
        pool.add(name)
    pool.add(ANDROID_NS_PREFIX)
    pool.add(ANDROID_NS)
    _collect_strings(root, pool)

    chunks: list[bytes] = []
    chunks.append(_encode_string_pool(pool.values))
    if attr_names:
        chunks.append(_encode_resource_map(attr_names))

    prefix_idx = pool.index(ANDROID_NS_PREFIX)
    uri_idx = pool.index(ANDROID_NS)
    chunks.append(_encode_namespace(RES_XML_START_NAMESPACE_TYPE, prefix_idx, uri_idx))
    chunks.extend(_encode_element(root, pool, line=2))
    chunks.append(_encode_namespace(RES_XML_END_NAMESPACE_TYPE, prefix_idx, uri_idx))

    body = b"".join(chunks)
    header = struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(body))
    return header + body


def xml_node_from_element_tree(element: Element) -> XmlNode:
    attrib = {}
    for key, value in element.attrib.items():
        attrib[_clark_to_prefixed(key)] = value
    node = XmlNode(name=_clark_to_prefixed(element.tag).split("}")[-1], attributes=attrib)
    if element.tag.startswith("{"):
        node.name = element.tag.split("}", 1)[1]
    for child in list(element):
        node.children.append(xml_node_from_element_tree(child))
    if element.text and element.text.strip():
        node.text = element.text.strip()
    return node


def to_element_tree(node: XmlNode) -> Element:
    element = Element(node.name, node.attributes)
    for child in node.children:
        element.append(to_element_tree(child))
    if node.text:
        element.text = node.text
    return element


def _parse_plaintext_xml(data: bytes) -> XmlNode:
    text = data.decode("utf-8-sig")
    if "android:" in text and "xmlns:android" not in text:
        text = text.replace("<manifest", f'<manifest xmlns:android="{ANDROID_NS}"', 1)
    try:
        element = ET.fromstring(text)
    except ET.ParseError as exc:
        raise AxmlError(f"invalid XML: {exc}") from exc
    return xml_node_from_element_tree(element)


def _chunk_header(data: bytes, offset: int) -> tuple[int, int, int]:
    chunk_type, header_size, size = struct.unpack_from("<HHI", data, offset)
    return chunk_type, header_size, size


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _string_at(strings: list[str], index: int) -> str:
    if index == NO_INDEX or index >= len(strings):
        return ""
    return strings[index]


def _parse_resource_map(data: bytes, offset: int, size: int) -> list[int]:
    ids: list[int] = []
    pos = offset + 8
    end = offset + size
    while pos + 4 <= end:
        ids.append(_u32(data, pos))
        pos += 4
    return ids


def _parse_string_pool(data: bytes, offset: int) -> list[str]:
    _ctype, header_size, size = _chunk_header(data, offset)
    string_count = _u32(data, offset + 8)
    style_count = _u32(data, offset + 12)
    flags = _u32(data, offset + 16)
    strings_start = _u32(data, offset + 20)
    utf8 = bool(flags & UTF8_FLAG)
    offsets_pos = offset + header_size
    strings: list[str] = []
    data_base = offset + strings_start
    for i in range(string_count):
        str_offset = _u32(data, offsets_pos + i * 4)
        abs_off = data_base + str_offset
        if utf8:
            strings.append(_decode_utf8_string(data, abs_off, offset + size))
        else:
            strings.append(_decode_utf16_string(data, abs_off, offset + size))
    _ = style_count  # styles unused for manifests
    return strings


def _decode_len_utf16(data: bytes, offset: int) -> tuple[int, int]:
    value = _u16(data, offset)
    if value & 0x8000:
        value = ((value & 0x7FFF) << 16) | _u16(data, offset + 2)
        return value, offset + 4
    return value, offset + 2


def _decode_len_utf8(data: bytes, offset: int) -> tuple[int, int]:
    value = data[offset]
    if value & 0x80:
        value = ((value & 0x7F) << 8) | data[offset + 1]
        return value, offset + 2
    return value, offset + 1


def _decode_utf16_string(data: bytes, offset: int, limit: int) -> str:
    length, pos = _decode_len_utf16(data, offset)
    end = pos + length * 2
    if end > limit or end > len(data):
        end = min(limit, len(data))
    raw = data[pos:end]
    return raw.decode("utf-16-le", errors="replace")


def _decode_utf8_string(data: bytes, offset: int, limit: int) -> str:
    _charlen, pos = _decode_len_utf8(data, offset)
    byte_len, pos = _decode_len_utf8(data, pos)
    end = pos + byte_len
    if end > limit or end > len(data):
        end = min(limit, len(data))
    return data[pos:end].decode("utf-8", errors="replace")


def _parse_start_element(
    data: bytes,
    offset: int,
    strings: list[str],
    resource_ids: list[int],
    namespaces: dict[str, str],
) -> XmlNode:
    _ctype, header_size, _csize = _chunk_header(data, offset)
    ext = offset + header_size
    name_idx = _u32(data, ext + 4)
    attr_start = _u16(data, ext + 8)
    attr_size = _u16(data, ext + 10) or 20
    attr_count = _u16(data, ext + 12)
    name = _string_at(strings, name_idx) or "node"
    node = XmlNode(name=name)
    attr_base = ext + attr_start
    for i in range(attr_count):
        aoff = attr_base + i * attr_size
        ns_idx = _u32(data, aoff)
        name_i = _u32(data, aoff + 4)
        raw_idx = _u32(data, aoff + 8)
        typed = _parse_res_value(data, aoff + 12, strings, raw_idx)
        local = _string_at(strings, name_i)
        if (not local) and name_i < len(resource_ids):
            local = ANDROID_ATTR_BY_ID.get(resource_ids[name_i], f"attr_{resource_ids[name_i]:08x}")
        elif name_i < len(resource_ids) and resource_ids[name_i] in ANDROID_ATTR_BY_ID:
            local = ANDROID_ATTR_BY_ID[resource_ids[name_i]]
        ns_uri = _string_at(strings, ns_idx)
        prefix = namespaces.get(ns_uri, ANDROID_NS_PREFIX if ns_uri == ANDROID_NS else "")
        key = f"{prefix}:{local}" if prefix and local else local
        node.attributes[key] = typed
    return node


def _parse_res_value(data: bytes, offset: int, strings: list[str], raw_idx: int) -> str:
    data_type = data[offset + 3]
    value = _u32(data, offset + 4)
    if data_type == TYPE_STRING:
        idx = value if value != NO_INDEX else raw_idx
        return _string_at(strings, idx)
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if value != 0 else "false"
    if data_type in {TYPE_INT_DEC, TYPE_INT_HEX}:
        return str(value)
    if data_type == TYPE_REFERENCE:
        return f"@{value:08x}"
    if data_type == TYPE_FLOAT:
        packed = struct.pack("<I", value)
        return str(struct.unpack("<f", packed)[0])
    if raw_idx != NO_INDEX:
        return _string_at(strings, raw_idx)
    return str(value)


class _StringPool:
    def __init__(self) -> None:
        self.values: list[str] = []
        self._index: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value in self._index:
            return self._index[value]
        idx = len(self.values)
        self._index[value] = idx
        self.values.append(value)
        return idx

    def index(self, value: str) -> int:
        return self._index[value]


def _collect_strings(node: XmlNode, pool: _StringPool) -> None:
    pool.add(node.name)
    for key, value in node.attributes.items():
        pool.add(_local_name(key))
        if not _is_int_like(value) and value not in {"true", "false"}:
            pool.add(value)
        elif _local_name(key) not in ANDROID_ATTR_ID_BY_NAME:
            pool.add(value)
    if node.text:
        pool.add(node.text)
    for child in node.children:
        _collect_strings(child, pool)


def _local_name(key: str) -> str:
    if key.startswith("{"):
        return key.split("}", 1)[1]
    if ":" in key:
        return key.split(":", 1)[1]
    return key


def _clark_to_prefixed(key: str) -> str:
    if key.startswith("{") and "}" in key:
        ns, local = key[1:].split("}", 1)
        if ns == ANDROID_NS:
            return f"android:{local}"
        return local
    return key


def _is_int_like(value: str) -> bool:
    if not value:
        return False
    if value.startswith("-") and value[1:].isdigit():
        return True
    return value.isdigit()


def _encode_string_pool(values: list[str]) -> bytes:
    offsets: list[int] = []
    blob = bytearray()
    for value in values:
        offsets.append(len(blob))
        encoded = value.encode("utf-16-le")
        char_len = len(value)
        if char_len >= 0x8000:
            blob += struct.pack("<HH", 0x8000 | ((char_len >> 16) & 0x7FFF), char_len & 0xFFFF)
        else:
            blob += struct.pack("<H", char_len)
        blob += encoded
        blob += b"\x00\x00"
    while len(blob) % 4:
        blob += b"\x00"
    header_size = 28
    strings_start = header_size + 4 * len(values)
    size = strings_start + len(blob)
    header = struct.pack(
        "<HHI",
        RES_STRING_POOL_TYPE,
        header_size,
        size,
    ) + struct.pack(
        "<IIIII",
        len(values),
        0,  # styleCount
        0,  # flags UTF-16
        strings_start,
        0,  # stylesStart
    )
    offset_bytes = b"".join(struct.pack("<I", off) for off in offsets)
    return header + offset_bytes + bytes(blob)


def _encode_resource_map(attr_names: list[str]) -> bytes:
    ids = [ANDROID_ATTR_ID_BY_NAME.get(name, 0) for name in attr_names]
    body = b"".join(struct.pack("<I", rid) for rid in ids)
    return struct.pack("<HHI", RES_XML_RESOURCE_MAP_TYPE, 8, 8 + len(body)) + body


def _encode_namespace(chunk_type: int, prefix_idx: int, uri_idx: int) -> bytes:
    return struct.pack(
        "<HHI II II",
        chunk_type,
        16,
        24,
        1,  # lineNumber
        NO_INDEX,  # comment
        prefix_idx,
        uri_idx,
    )


def _encode_element(node: XmlNode, pool: _StringPool, line: int) -> list[bytes]:
    chunks: list[bytes] = []
    attrs = list(node.attributes.items())
    attr_blob = bytearray()
    for key, value in attrs:
        local = _local_name(key)
        if key.startswith("android:") or (local in ANDROID_ATTR_ID_BY_NAME and key != "package"):
            ns_idx = pool.index(ANDROID_NS)
        else:
            ns_idx = NO_INDEX
        name_idx = pool.index(local)
        raw_idx, data_type, data_value = _encode_typed_value(local, value, pool)
        attr_blob += struct.pack("<III", ns_idx, name_idx, raw_idx)
        attr_blob += struct.pack("<HBBI", 8, 0, data_type, data_value)

    name_idx = pool.index(node.name)
    header_size = 16
    attr_start = 20
    attr_count = len(attrs)
    chunk_size = header_size + attr_start + 20 * attr_count
    start = (
        struct.pack("<HHI", RES_XML_START_ELEMENT_TYPE, header_size, chunk_size)
        + struct.pack("<II", line, NO_INDEX)
        + struct.pack("<II", NO_INDEX, name_idx)
        + struct.pack("<HHHHHH", attr_start, 20, attr_count, 0, 0, 0)
    )
    chunks.append(start + bytes(attr_blob))
    child_line = line + 1
    for child in node.children:
        chunks.extend(_encode_element(child, pool, child_line))
        child_line += 1
    end = (
        struct.pack("<HHI", RES_XML_END_ELEMENT_TYPE, 16, 24)
        + struct.pack("<II", line, NO_INDEX)
        + struct.pack("<II", NO_INDEX, name_idx)
    )
    chunks.append(end)
    return chunks


def _encode_typed_value(local: str, value: str, pool: _StringPool) -> tuple[int, int, int]:
    if value in {"true", "false"}:
        return NO_INDEX, TYPE_INT_BOOLEAN, (0xFFFFFFFF if value == "true" else 0)
    int_attrs = {
        "versionCode",
        "minSdkVersion",
        "targetSdkVersion",
        "maxSdkVersion",
        "priority",
    }
    if local in int_attrs and _is_int_like(value):
        return NO_INDEX, TYPE_INT_DEC, int(value) & 0xFFFFFFFF
    if _is_int_like(value) and local in ANDROID_ATTR_ID_BY_NAME:
        return NO_INDEX, TYPE_INT_DEC, int(value) & 0xFFFFFFFF
    idx = pool.add(value)
    return idx, TYPE_STRING, idx


def node_to_dict(node: XmlNode) -> dict[str, Any]:
    return {
        "name": node.name,
        "attributes": node.attributes,
        "text": node.text,
        "children": [node_to_dict(child) for child in node.children],
    }
