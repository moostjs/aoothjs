import { describe, it, expect } from "vite-plus/test";
import { getValue, setValue, unsetAll } from "./get-set";

describe("get-set", () => {
  describe("getValue", () => {
    it("must get top-level property", () => {
      expect(getValue({ a: 1 }, "a")).toBe(1);
    });

    it("must get nested property", () => {
      expect(getValue({ a: { b: { c: 42 } } }, "a.b.c")).toBe(42);
    });

    it("must return undefined for missing intermediate", () => {
      expect(getValue({ a: {} }, "a.b.c")).toBeUndefined();
    });

    it("must return undefined for missing top-level", () => {
      expect(getValue({}, "x")).toBeUndefined();
    });

    it("must access array elements by index", () => {
      expect(getValue({ items: [10, 20, 30] }, "items.1")).toBe(20);
    });
  });

  describe("setValue", () => {
    it("must set top-level property", () => {
      const obj: Record<string, unknown> = {};
      setValue(obj, "x", 5);
      expect(obj.x).toBe(5);
    });

    it("must set nested property", () => {
      const obj = { a: { b: 0 } };
      setValue(obj, "a.b", 99);
      expect(obj.a.b).toBe(99);
    });

    it("must create intermediate objects", () => {
      const obj: Record<string, unknown> = {};
      setValue(obj, "a.b.c", "deep");
      expect((obj as any).a.b.c).toBe("deep");
    });

    it("must create intermediate array when next part is numeric", () => {
      const obj: Record<string, unknown> = {};
      setValue(obj, "items.0", "first");
      expect(Array.isArray((obj as any).items)).toBe(true);
      expect((obj as any).items[0]).toBe("first");
    });

    it("must unset a property", () => {
      const obj = { a: 1, b: 2 };
      setValue(obj, "a", undefined, "unset");
      expect("a" in obj).toBe(false);
      expect(obj.b).toBe(2);
    });

    it("must return early on unset with missing intermediate", () => {
      const obj = { a: {} };
      // should not throw
      setValue(obj, "a.b.c", undefined, "unset");
      expect((obj as any).a.b).toBeUndefined();
    });

    it("must increment existing value", () => {
      const obj = { count: 5 };
      setValue(obj, "count", 3, "inc");
      expect(obj.count).toBe(8);
    });

    it("must increment missing value from 0", () => {
      const obj: Record<string, unknown> = {};
      setValue(obj, "count", 1, "inc");
      expect(obj.count).toBe(1);
    });

    it("must increment nested value", () => {
      const obj = { stats: { hits: 10 } };
      setValue(obj, "stats.hits", 5, "inc");
      expect(obj.stats.hits).toBe(15);
    });
  });

  describe("unsetAll", () => {
    it("must remove all properties", () => {
      const obj = { a: 1, b: 2, c: 3 };
      unsetAll(obj);
      expect(Object.keys(obj)).toHaveLength(0);
    });

    it("must handle empty object", () => {
      const obj = {};
      unsetAll(obj);
      expect(Object.keys(obj)).toHaveLength(0);
    });
  });
});
