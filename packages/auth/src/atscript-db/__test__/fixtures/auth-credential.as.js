// prettier-ignore-start
/* eslint-disable */
/* oxlint-disable */
import { defineAnnotatedType as $, annotate as $a, throwFeatureDisabled as $d } from "@atscript/typescript/utils"

export class AoothAuthCredential {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "AoothAuthCredential"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}

$("object", AoothAuthCredential)
  .prop(
    "token",
    $().designType("string")
      .tags("string")
      .annotate("meta.id", true)
      .$type
  ).prop(
    "userId",
    $().designType("string")
      .tags("string")
      .annotate("db.index.plain", { }, true)
      .$type
  ).prop(
    "issuedAt",
    $().designType("number")
      .tags("timestamp", "number")
      .annotate("expect.int", true)
      .$type
  ).prop(
    "expiresAt",
    $().designType("number")
      .tags("timestamp", "number")
      .annotate("expect.int", true)
      .$type
  ).prop(
    "kind",
    $().designType("string")
      .tags("string")
      .optional()
      .$type
  ).prop(
    "claims",
    $("object")
      .propPattern(
        /.*/,
        $("union")
          .item($().designType("string")
              .tags("string")
              .$type)
          .item($().designType("number")
              .tags("number")
              .$type)
          .item($().designType("boolean")
              .tags("boolean")
              .$type)
          .$type
      )
      .annotate("db.json", true)
      .optional()
      .$type
  ).prop(
    "metadata",
    $("object")
      .prop(
        "ip",
        $().designType("string")
          .tags("string")
          .optional()
          .$type
      ).prop(
        "userAgent",
        $().designType("string")
          .tags("string")
          .optional()
          .$type
      ).prop(
        "fingerprint",
        $().designType("string")
          .tags("string")
          .optional()
          .$type
      ).prop(
        "label",
        $().designType("string")
          .tags("string")
          .optional()
          .$type
      )
      .annotate("db.json", true)
      .optional()
      .$type
  ).prop(
    "parentCredentialId",
    $().designType("string")
      .tags("string")
      .optional()
      .$type
  ).prop(
    "rotatedAt",
    $().designType("number")
      .tags("timestamp", "number")
      .annotate("expect.int", true)
      .optional()
      .$type
  )
  .annotate("db.table", "aooth_credentials")
  .annotate("db.depth.limit", 0)

// prettier-ignore-end