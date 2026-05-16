import { describe, expect, it } from "vite-plus/test";

import {
  Arbac,
  ArbacAction,
  ArbacAuthorize,
  arbacAuthorizeInterceptor,
  ArbacResource,
  ArbacScopes,
  ArbacUserProvider,
  getArbacMate,
  MoostArbac,
  useArbac,
} from "./index";
import * as indexModule from "./index";
import * as atscriptModule from "./atscript/index";

describe("@aoothjs/arbac-moost", () => {
  it("re-exports arbac-core engine", () => {
    expect(Arbac).toBeDefined();
    expect(typeof Arbac).toBe("function");
  });

  it("exports MoostArbac as a class extending Arbac", () => {
    expect(MoostArbac).toBeDefined();
    expect(new MoostArbac()).toBeInstanceOf(Arbac);
  });

  it("exports ArbacUserProvider with the three abstract-style methods", async () => {
    expect(ArbacUserProvider).toBeDefined();
    const provider = new ArbacUserProvider();
    expect(typeof provider.getUserId).toBe("function");
    expect(typeof provider.getRoles).toBe("function");
    expect(typeof provider.getAttrs).toBe("function");
    // base methods reject — must be overridden
    await expect(Promise.resolve(provider.getUserId())).rejects.toBeInstanceOf(Error);
  });

  it("exports arbacAuthorizeInterceptor as a moost auth-guard def", () => {
    expect(arbacAuthorizeInterceptor).toBeDefined();
    expect(typeof arbacAuthorizeInterceptor).toBe("object");
    expect(typeof arbacAuthorizeInterceptor.before).toBe("function");
    expect(arbacAuthorizeInterceptor.priority).toBeDefined();
    // swagger-readable transport metadata marker
    expect(arbacAuthorizeInterceptor.__authTransports).toEqual({});
  });

  it("exports decorator factories that return functions", () => {
    expect(typeof ArbacAuthorize).toBe("function");
    expect(typeof ArbacScopes).toBe("function");
    expect(typeof ArbacResource).toBe("function");
    expect(typeof ArbacAction).toBe("function");
    // each factory must return a usable decorator
    expect(typeof ArbacAuthorize()).toBe("function");
    expect(typeof ArbacResource("res.user")).toBe("function");
    expect(typeof ArbacAction("create")).toBe("function");
    expect(typeof ArbacScopes()).toBe("function");
  });

  it("getArbacMate returns the moost mate singleton typed for ARBAC", () => {
    const mate = getArbacMate();
    expect(mate).toBeDefined();
    expect(typeof mate.decorate).toBe("function");
    expect(typeof mate.read).toBe("function");
  });

  it("useArbac is a wook composable function", () => {
    expect(typeof useArbac).toBe("function");
    // defineWook attaches an underlying _slot for isolation use
    expect(useArbac._slot).toBeDefined();
  });

  it("CurrentArbacScopes is NOT exported (hard-cut alias removal — ISSUE-3)", () => {
    // ArbacScopes is the canonical export; CurrentArbacScopes was a needless alias.
    // Any re-introduction of the alias would silently add a second way to do the same
    // thing and break the hard-cut contract — this test catches that regression.
    expect("CurrentArbacScopes" in indexModule).toBe(false);
  });

  it("applyArbacGuardGlobally is NOT exported (hard-cut removal — ISSUE-7)", () => {
    // The wrapper was deleted; callers must use app.applyGlobalInterceptors(arbacAuthorizeInterceptor)
    // directly. Keeping this test ensures no one silently re-introduces the helper and
    // re-creates an abstraction that adds zero value over the bare Moost API.
    expect("applyArbacGuardGlobally" in indexModule).toBe(false);
  });

  it("ArbacResource decorator writes resource id metadata", () => {
    class Probe {
      _name = "probe";
    }
    ArbacResource("probe.resource")(Probe);
    const meta = getArbacMate().read(Probe);
    expect(meta?.arbacResourceId).toBe("probe.resource");
  });

  it("ArbacPublic is NOT exported (hard-cut removal — ISSUE-4)", () => {
    // ArbacPublic was collapsed into auth-moost's combined @Public(). The
    // `arbacPublic` mate flag still exists and is written by @Public(),
    // but no standalone arbac-only bypass decorator is exported.
    expect("ArbacPublic" in indexModule).toBe(false);
  });

  // ISSUE-9: the legacy AutoArbacUserProvider + the loose helper functions
  // (setUserRecordFetcher / useUserRecord / setupArbacFromAtscript / the
  // extract* + projection getters) were collapsed into the new abstract
  // AtscriptArbacUserProvider. Re-introducing any of them would re-fork the
  // DI surface and silently re-create the two-ways-to-do-the-same-thing
  // problem the refactor was meant to kill — these negatives guard that.
  describe("ISSUE-9 hard-cut removals", () => {
    it("AutoArbacUserProvider is NOT exported from the root barrel", () => {
      expect("AutoArbacUserProvider" in indexModule).toBe(false);
    });

    it("setUserRecordFetcher is NOT exported (absorbed into AtscriptArbacUserProvider)", () => {
      expect("setUserRecordFetcher" in indexModule).toBe(false);
      expect("setUserRecordFetcher" in atscriptModule).toBe(false);
    });

    it("useUserRecord is NOT exported (replaced by the provider's per-event memoization)", () => {
      expect("useUserRecord" in indexModule).toBe(false);
      expect("useUserRecord" in atscriptModule).toBe(false);
    });

    it("setupArbacFromAtscript is NOT exported (consumers wire DI directly)", () => {
      expect("setupArbacFromAtscript" in indexModule).toBe(false);
      expect("setupArbacFromAtscript" in atscriptModule).toBe(false);
    });

    it("getArbacProjection is NOT exported (module-local cache only)", () => {
      expect("getArbacProjection" in indexModule).toBe(false);
      expect("getArbacProjection" in atscriptModule).toBe(false);
    });

    it("getArbacExtractSpec is NOT exported (module-local cache only)", () => {
      expect("getArbacExtractSpec" in indexModule).toBe(false);
      expect("getArbacExtractSpec" in atscriptModule).toBe(false);
    });

    it("extractArbacUserId is NOT exported (folded into provider)", () => {
      expect("extractArbacUserId" in indexModule).toBe(false);
      expect("extractArbacUserId" in atscriptModule).toBe(false);
    });

    it("extractArbacRoles is NOT exported (replaced by protected extractRoles seam)", () => {
      expect("extractArbacRoles" in indexModule).toBe(false);
      expect("extractArbacRoles" in atscriptModule).toBe(false);
    });

    it("extractArbacAttrs is NOT exported (replaced by protected extractAttrs seam)", () => {
      expect("extractArbacAttrs" in indexModule).toBe(false);
      expect("extractArbacAttrs" in atscriptModule).toBe(false);
    });
  });

  // ISSUE-9 positive: the canonical replacement is `AtscriptArbacUserProvider`,
  // an abstract class shipped from the `/atscript` subpath. Consumers extend it,
  // implement `getUserId`, and register the subclass via `setReplaceRegistry`.
  describe("ISSUE-9 AtscriptArbacUserProvider public surface", () => {
    it("is exported from the /atscript subpath barrel", () => {
      expect("AtscriptArbacUserProvider" in atscriptModule).toBe(true);
      const ctor = atscriptModule.AtscriptArbacUserProvider as unknown as Function;
      expect(typeof ctor).toBe("function");
    });

    it("is abstract (instantiating the base class without a subclass throws)", () => {
      // `abstract` is a compile-time check; at runtime the class is constructible.
      // The intent we encode here is that the constructor demands a real
      // annotated type and a real table — without them it must fail loud.
      const Ctor = atscriptModule.AtscriptArbacUserProvider as unknown as new (
        ...args: unknown[]
      ) => unknown;
      expect(() => new Ctor()).toThrow();
    });
  });
});
