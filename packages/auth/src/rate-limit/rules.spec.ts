import { describe, expect, it } from "vite-plus/test";

import {
  formatDurationMs,
  parseDurationMs,
  parseRateLimitRule,
  renderRateLimitMessage,
} from "./rules";

describe("parseDurationMs", () => {
  it("parses every unit", () => {
    expect(parseDurationMs("500ms")).toBe(500);
    expect(parseDurationMs("90s")).toBe(90_000);
    expect(parseDurationMs("5m")).toBe(300_000);
    expect(parseDurationMs("1h")).toBe(3_600_000);
    expect(parseDurationMs("2d")).toBe(172_800_000);
  });

  it("rejects unknown units and bare numbers", () => {
    expect(() => parseDurationMs("5x")).toThrow(/Invalid rate-limit window/);
    expect(() => parseDurationMs("5")).toThrow(/Invalid rate-limit window/);
    expect(() => parseDurationMs("m5")).toThrow(/Invalid rate-limit window/);
  });
});

describe("parseRateLimitRule", () => {
  it("parses the slash form", () => {
    expect(parseRateLimitRule("6/5m")).toEqual({ limit: 6, window: 300_000 });
  });

  it("parses the 'per' form", () => {
    expect(parseRateLimitRule("30 per 1m")).toEqual({ limit: 30, window: 60_000 });
  });

  it("parses an inline message after the pipe", () => {
    expect(parseRateLimitRule("6/5m | Too many attempts, wait {{delta}}")).toEqual({
      limit: 6,
      window: 300_000,
      message: "Too many attempts, wait {{delta}}",
    });
  });

  it("normalizes object rules with string windows", () => {
    expect(parseRateLimitRule({ limit: 5, window: "5m" })).toEqual({ limit: 5, window: 300_000 });
    expect(parseRateLimitRule({ limit: 5, window: 1000 })).toEqual({ limit: 5, window: 1000 });
  });

  it("rejects bad grammar and non-positive values at parse time (boot, not per request)", () => {
    expect(() => parseRateLimitRule("6-5m")).toThrow(/Invalid rate-limit rule/);
    expect(() => parseRateLimitRule("0/5m")).toThrow(/positive integer/);
    expect(() => parseRateLimitRule({ limit: 1.5, window: 1000 })).toThrow(/positive integer/);
    expect(() => parseRateLimitRule({ limit: 1, window: 0 })).toThrow(/positive ms/);
  });
});

describe("formatDurationMs", () => {
  it("humanizes with at most two units", () => {
    expect(formatDurationMs(300_000)).toBe("5 minutes");
    expect(formatDurationMs(272_000)).toBe("4 minutes 32 seconds");
    expect(formatDurationMs(3_600_000)).toBe("1 hour");
    expect(formatDurationMs(90_060_000)).toBe("1 day 1 hour");
  });

  it("rounds sub-second values UP — a '0 seconds' retry hint reads as broken", () => {
    expect(formatDurationMs(1)).toBe("1 second");
    expect(formatDurationMs(1500)).toBe("2 seconds");
  });
});

describe("renderRateLimitMessage", () => {
  it("substitutes limit/max/window/delta placeholders", () => {
    const rule = { limit: 6, window: 300_000 };
    expect(
      renderRateLimitMessage(
        "Max {{max}} ({{limit}}) per {{window}}; wait {{delta}}",
        rule,
        272_000,
      ),
    ).toBe("Max 6 (6) per 5 minutes; wait 4 minutes 32 seconds");
  });
});
