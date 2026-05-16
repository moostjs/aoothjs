import { describe, expect, it } from "vite-plus/test";

import * as indexModule from "../index";
import { getAuthMate } from "../auth.mate";
import { Public } from "../auth.decorator";

// ISSUE-9: `setupAuthMoost` was deleted. Consumers now call
// setProvideRegistry / applyGlobalInterceptors / registerControllers
// directly — see controller-utils.ts for the canonical wiring.
// Re-introducing the helper would re-create the abstraction tax the
// refactor removed; this negative pins it shut at the barrel level.
describe("@aoothjs/auth-moost ISSUE-9 hard-cut removals", () => {
  it("setupAuthMoost is NOT exported from the root barrel", () => {
    expect("setupAuthMoost" in indexModule).toBe(false);
  });
});

describe("@Public decorator", () => {
  it("writes authPublic=true at the class level", () => {
    class ClassProbe {
      _name = "cls";
    }
    Public()(ClassProbe);
    const meta = getAuthMate().read(ClassProbe);
    expect(meta?.authPublic).toBe(true);
  });

  it("writes authPublic=true at the method level", () => {
    class MethodProbe {
      _name = "mth";
      hello() {
        return "hello";
      }
    }
    const desc = Object.getOwnPropertyDescriptor(MethodProbe.prototype, "hello");
    Public()(MethodProbe.prototype, "hello", desc as PropertyDescriptor);
    const meta = getAuthMate().read(MethodProbe, "hello");
    expect(meta?.authPublic).toBe(true);
  });

  it("method-level @Public is readable independently from the class-level value", () => {
    class Mixed {
      _name = "mix";
      handler() {
        return "ok";
      }
    }
    // Class is protected by default — no @Public on the class.
    const handlerDesc = Object.getOwnPropertyDescriptor(Mixed.prototype, "handler");
    Public()(Mixed.prototype, "handler", handlerDesc as PropertyDescriptor);

    const cMeta = getAuthMate().read(Mixed);
    const mMeta = getAuthMate().read(Mixed, "handler");
    // class-level meta does NOT inherit the method-level decoration.
    expect(cMeta?.authPublic).toBeUndefined();
    expect(mMeta?.authPublic).toBe(true);
  });
});
