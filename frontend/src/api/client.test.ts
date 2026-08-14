import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiFetch } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiFetch", () => {
  it("surfaces backend error messages without stack traces", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ detail: "Invalid application. AppProbe expected an APK." }),
      }),
    );
    await expect(apiFetch("/scans")).rejects.toBeInstanceOf(ApiError);
    await expect(apiFetch("/scans")).rejects.toMatchObject({
      message: "Invalid application. AppProbe expected an APK.",
      status: 400,
    });
  });

  it("parses successful JSON responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        headers: { get: () => "application/json" },
        json: async () => ({ id: "abc" }),
      }),
    );
    await expect(apiFetch<{ id: string }>("/scans")).resolves.toEqual({ id: "abc" });
  });
});
