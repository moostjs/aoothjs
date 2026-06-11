import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { describe, expect, it } from "vite-plus/test";

import { mockAnnotatedType } from "./__test__/mock-annotated-type";
import { getAoothCredentialMetadataSpec } from "./credential-metadata-spec";

const METADATA = "aooth.auth.metadata";
const JSON_COL = "db.json";

describe("getAoothCredentialMetadataSpec — @aooth.auth.metadata resolution", () => {
  it("discovers the annotated @db.json metadata column", () => {
    const spec = getAoothCredentialMetadataSpec(
      mockAnnotatedType({
        token: {},
        userId: {},
        metadata: { [METADATA]: true, [JSON_COL]: true },
      }),
    );
    expect(spec.metadataField).toBe("metadata");
    expect(spec.warnings).toEqual([]);
  });

  it("resolves name-agnostically — the field need not be named 'metadata'", () => {
    const spec = getAoothCredentialMetadataSpec(
      mockAnnotatedType({ sessionMeta: { [METADATA]: true, [JSON_COL]: true } }),
    );
    expect(spec.metadataField).toBe("sessionMeta");
  });

  it("returns undefined + no warnings for a model with no annotated field (graceful degradation)", () => {
    const spec = getAoothCredentialMetadataSpec(
      mockAnnotatedType({ token: {}, grants: { [JSON_COL]: true } }),
    );
    expect(spec.metadataField).toBeUndefined();
    expect(spec.warnings).toEqual([]);
  });

  it("warn-and-disable: an annotated field without @db.json is dropped with a warning", () => {
    const spec = getAoothCredentialMetadataSpec(
      mockAnnotatedType({ metadata: { [METADATA]: true } }),
    );
    expect(spec.metadataField).toBeUndefined();
    expect(spec.warnings).toHaveLength(1);
    expect(spec.warnings[0]).toMatch(/@aooth\.auth\.metadata/);
    expect(spec.warnings[0]).toMatch(/no @db\.json/);
  });

  it("throws on more than one @aooth.auth.metadata field (ambiguity)", () => {
    expect(() =>
      getAoothCredentialMetadataSpec(
        mockAnnotatedType({
          metadata: { [METADATA]: true, [JSON_COL]: true },
          altMetadata: { [METADATA]: true, [JSON_COL]: true },
        }),
      ),
    ).toThrow(/multiple @aooth\.auth\.metadata/);
  });

  it("caches the spec per type (same reference returned)", () => {
    const t = mockAnnotatedType({ metadata: { [METADATA]: true, [JSON_COL]: true } });
    expect(getAoothCredentialMetadataSpec(t)).toBe(getAoothCredentialMetadataSpec(t));
  });

  it("handles a non-object type gracefully", () => {
    const spec = getAoothCredentialMetadataSpec({
      type: { kind: "string" },
    } as unknown as TAtscriptAnnotatedType);
    expect(spec.metadataField).toBeUndefined();
    expect(spec.warnings).toEqual([]);
  });
});
