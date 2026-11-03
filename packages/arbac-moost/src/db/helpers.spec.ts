import { describe, expect, it } from "vite-plus/test";

import { isKeyObject } from "./helpers";

class FakeObjectId {
  constructor(private readonly hex: string) {}
  toString(): string {
    return this.hex;
  }
}

describe("isKeyObject", () => {
  it("treats a plain object as a composite key", () => {
    expect(isKeyObject({ left: 1, right: "a" })).toBe(true);
    expect(isKeyObject(Object.assign(Object.create(null), { id: 1 }))).toBe(true);
  });

  it("treats scalars and class instances (a MongoDB ObjectId) as scalar ids", () => {
    expect(isKeyObject(7)).toBe(false);
    expect(isKeyObject("abc")).toBe(false);
    expect(isKeyObject(null)).toBe(false);
    expect(isKeyObject(new FakeObjectId("665f1c2e9b1d4a0012ab34cd"))).toBe(false);
  });
});
