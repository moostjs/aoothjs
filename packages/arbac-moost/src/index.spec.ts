import { describe, expect, it } from "vite-plus/test";

import {
  Arbac,
  ArbacAction,
  ArbacAuthorize,
  arbacAuthorizeInterceptor,
  ArbacPublic,
  ArbacResource,
  ArbacScopes,
  ArbacUserProvider,
  CurrentArbacScopes,
  getArbacMate,
  MoostArbac,
  useArbac,
} from "./index";

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

  it("exports arbacAuthorizeInterceptor as a TInterceptorDef", () => {
    expect(arbacAuthorizeInterceptor).toBeDefined();
    expect(typeof arbacAuthorizeInterceptor).toBe("object");
    expect(typeof arbacAuthorizeInterceptor.before).toBe("function");
    expect(arbacAuthorizeInterceptor.priority).toBeDefined();
  });

  it("exports decorator factories that return functions", () => {
    expect(typeof ArbacAuthorize).toBe("function");
    expect(typeof ArbacScopes).toBe("function");
    expect(typeof CurrentArbacScopes).toBe("function");
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

  it("CurrentArbacScopes is the ArbacScopes alias", () => {
    expect(CurrentArbacScopes).toBe(ArbacScopes);
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
