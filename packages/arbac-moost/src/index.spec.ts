import { describe, expect, it } from "vite-plus/test";

import {
  applyArbacGuardGlobally,
  Arbac,
  ArbacAction,
  ArbacAuthorize,
  arbacAuthorizeInterceptor,
  ArbacPublic,
  ArbacResource,
  ArbacScopes,
  ArbacUserProvider,
  getArbacMate,
  MoostArbac,
  useArbac,
} from "./index";
import * as indexModule from "./index";

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

  it("exports applyArbacGuardGlobally helper", () => {
    expect(typeof applyArbacGuardGlobally).toBe("function");
  });

  it("exports decorator factories that return functions", () => {
    expect(typeof ArbacAuthorize).toBe("function");
    expect(typeof ArbacScopes).toBe("function");
    expect(typeof ArbacResource).toBe("function");
    expect(typeof ArbacAction).toBe("function");
    expect(typeof ArbacPublic).toBe("function");
    // each factory must return a usable decorator
    expect(typeof ArbacAuthorize()).toBe("function");
    expect(typeof ArbacResource("res.user")).toBe("function");
    expect(typeof ArbacAction("create")).toBe("function");
    expect(typeof ArbacPublic()).toBe("function");
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

  it("ArbacResource decorator writes resource id metadata", () => {
    class Probe {
      _name = "probe";
    }
    ArbacResource("probe.resource")(Probe);
    const meta = getArbacMate().read(Probe);
    expect(meta?.arbacResourceId).toBe("probe.resource");
  });

  it("ArbacPublic decorator marks the target as public", () => {
    class PublicProbe {
      _name = "public-probe";
    }
    ArbacPublic()(PublicProbe);
    const meta = getArbacMate().read(PublicProbe);
    expect(meta?.arbacPublic).toBe(true);
  });
});
