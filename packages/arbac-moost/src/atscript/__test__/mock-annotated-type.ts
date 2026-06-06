import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

/**
 * Build a minimal `TAtscriptAnnotatedType` whose object props carry the given
 * per-field annotation map — exactly the surface the atscript annotation walks
 * read (`type.kind`, `type.props`, `fieldType.metadata.get`). Lets the
 * extractor unit tests run without compiling an `.as` fixture.
 */
export function mockAnnotatedType(
  fields: Record<string, Record<string, unknown>>,
): TAtscriptAnnotatedType {
  const props = new Map<string, { metadata: { get: (k: string) => unknown } }>();
  for (const [name, anns] of Object.entries(fields)) {
    props.set(name, { metadata: { get: (k: string) => anns[k] } });
  }
  return { type: { kind: "object", props } } as unknown as TAtscriptAnnotatedType;
}
