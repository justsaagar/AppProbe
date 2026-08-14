import { describe, expect, it } from "vitest";
import { formatBytes, formatPercent, severityClass, validateUpload } from "./format";

const config = {
  max_upload_bytes: 200 * 1024 * 1024,
  allowed_extensions: [".apk", ".aab", ".ipa"],
};

describe("validateUpload", () => {
  it("rejects unsupported extensions", () => {
    const file = new File(["hello"], "notes.txt", { type: "text/plain" });
    expect(validateUpload(file, config)).toMatch(/unsupported file/i);
  });

  it("rejects oversized files using the backend limit", () => {
    const file = new File(["x".repeat(20)], "app.apk", { type: "application/vnd.android.package-archive" });
    expect(validateUpload(file, { ...config, max_upload_bytes: 10 })).toMatch(/configured size limit/i);
  });

  it("accepts APK files within the backend limit", () => {
    const file = new File(["pk"], "release.apk", { type: "application/vnd.android.package-archive" });
    expect(validateUpload(file, config)).toBeNull();
  });
});

describe("severityClass", () => {
  it("maps semantic severity colors", () => {
    expect(severityClass("CRITICAL")).toContain("critical");
    expect(severityClass("HIGH")).toContain("high");
    expect(severityClass("MEDIUM")).toContain("medium");
    expect(severityClass("LOW")).toContain("low");
    expect(severityClass("INFO")).toContain("info");
  });
});

describe("format helpers", () => {
  it("formats bytes and confidence", () => {
    expect(formatBytes(84.6 * 1024 * 1024)).toMatch(/MB/);
    expect(formatPercent(0.99)).toBe("99%");
  });
});
