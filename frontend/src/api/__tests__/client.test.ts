import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetchHealth, fetchStatus, fetchAlerts } from "../client";

describe("API Client", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("fetches health status successfully", async () => {
    const mockHealth = {
      status: "ok",
      model_loaded: true,
      model_version: "v1.0.0",
      schema_version: "1.0.0",
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockHealth,
    });

    const result = await fetchHealth();
    expect(result).toEqual(mockHealth);
    expect(globalThis.fetch).toHaveBeenCalledWith("http://127.0.0.1:8000/health");
  });

  it("fetches alerts with query parameters", async () => {
    const mockAlerts = {
      total: 1,
      offset: 0,
      limit: 10,
      items: [],
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockAlerts,
    });

    const result = await fetchAlerts({ limit: 10, threat_class: "DDOS" });
    expect(result).toEqual(mockAlerts);
    expect(globalThis.fetch).toHaveBeenCalledWith("http://127.0.0.1:8000/api/v1/alerts?limit=10&threat_class=DDOS");
  });

  it("throws error when response is not ok", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
    });

    await expect(fetchStatus()).rejects.toThrow("Status fetch failed: HTTP 503");
  });
});
