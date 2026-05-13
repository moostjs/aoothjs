import { describe, expect, it } from "vite-plus/test";

import arbacPlugin from "../../plugin";

describe("arbacPlugin", () => {
  it("is a no-arg factory returning a TAtscriptPlugin shape", () => {
    expect(typeof arbacPlugin).toBe("function");
    const plugin = arbacPlugin();
    expect(plugin).toBeDefined();
    expect(plugin.name).toBe("aoothjs-arbac");
    expect(typeof plugin.config).toBe("function");
  });

  it("registers the @arbac.* annotation namespace", () => {
    const plugin = arbacPlugin();
    const cfg = plugin.config?.({} as any);
    expect(cfg).toBeDefined();
    const annotations = (cfg as { annotations: { arbac: Record<string, unknown> } }).annotations;
    expect(annotations).toBeDefined();
    expect(annotations.arbac).toBeDefined();
    expect(annotations.arbac.role).toBeDefined();
    expect(annotations.arbac.attribute).toBeDefined();
    expect(annotations.arbac.userId).toBeDefined();
  });

  it("scopes every @arbac.* annotation to props with multiple: false", () => {
    const plugin = arbacPlugin();
    const cfg = plugin.config?.({} as any);
    const ann = (cfg as { annotations: { arbac: Record<string, any> } }).annotations.arbac;
    for (const key of ["role", "attribute", "userId"] as const) {
      const spec = ann[key];
      // AnnotationSpec exposes the config object — fields land on spec.config.
      expect(spec.__is_annotation_spec).toBe(true);
      expect(spec.config.nodeType).toEqual(["prop"]);
      expect(spec.config.multiple).toBe(false);
      expect(typeof spec.config.description).toBe("string");
    }
  });
});
