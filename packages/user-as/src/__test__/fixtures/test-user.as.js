// prettier-ignore-start
/* eslint-disable */
/* oxlint-disable */
import { defineAnnotatedType as $, annotate as $a, throwFeatureDisabled as $d } from "@atscript/typescript/utils"

export class AoothUserCredentials {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "AoothUserCredentials"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}

$("object", AoothUserCredentials)
  .prop(
    "id",
    $().designType("string")
      .tags("string")
      .annotate("meta.id", true)
      .annotate("db.default.uuid", true)
      .$type
  ).prop(
    "username",
    $().designType("string")
      .tags("string")
      .annotate("db.index.unique", "username_idx", true)
      .$type
  ).prop(
    "password",
    $("object")
      .prop(
        "hash",
        $().designType("string")
          .tags("string")
          .$type
      ).prop(
        "salt",
        $().designType("string")
          .tags("string")
          .$type
      ).prop(
        "algorithm",
        $().designType("string")
          .tags("string")
          .$type
      ).prop(
        "history",
        $("array")
          .of($("object")
              .prop(
                "algorithm",
                $().designType("string")
                  .tags("string")
                  .$type
              ).prop(
                "hash",
                $().designType("string")
                  .tags("string")
                  .$type
              )
              .$type)
          .annotate("db.json", true)
          .$type
      ).prop(
        "lastChanged",
        $().designType("number")
          .tags("timestamp", "number")
          .annotate("expect.int", true)
          .$type
      ).prop(
        "isInitial",
        $().designType("boolean")
          .tags("boolean")
          .$type
      )
      .annotate("db.patch.strategy", "merge")
      .$type
  ).prop(
    "account",
    $("object")
      .prop(
        "active",
        $().designType("boolean")
          .tags("boolean")
          .$type
      ).prop(
        "locked",
        $().designType("boolean")
          .tags("boolean")
          .$type
      ).prop(
        "lockReason",
        $().designType("string")
          .tags("string")
          .$type
      ).prop(
        "lockEnds",
        $().designType("number")
          .tags("timestamp", "number")
          .annotate("expect.int", true)
          .$type
      ).prop(
        "failedLoginAttempts",
        $().designType("number")
          .tags("number")
          .$type
      ).prop(
        "lastLogin",
        $().designType("number")
          .tags("timestamp", "number")
          .annotate("expect.int", true)
          .$type
      )
      .annotate("db.patch.strategy", "merge")
      .$type
  ).prop(
    "mfa",
    $("object")
      .prop(
        "email",
        $("object")
          .prop(
            "address",
            $().designType("string")
              .tags("string")
              .$type
          ).prop(
            "confirmed",
            $().designType("boolean")
              .tags("boolean")
              .$type
          )
          .annotate("db.patch.strategy", "merge")
          .$type
      ).prop(
        "sms",
        $("object")
          .prop(
            "confirmed",
            $().designType("boolean")
              .tags("boolean")
              .$type
          ).prop(
            "number",
            $().designType("string")
              .tags("string")
              .$type
          )
          .annotate("db.patch.strategy", "merge")
          .$type
      ).prop(
        "totp",
        $("object")
          .prop(
            "secretKey",
            $().designType("string")
              .tags("string")
              .$type
          )
          .annotate("db.patch.strategy", "merge")
          .$type
      ).prop(
        "default",
        $().designType("string")
          .tags("string")
          .$type
      ).prop(
        "autoSend",
        $().designType("boolean")
          .tags("boolean")
          .$type
      )
      .annotate("db.patch.strategy", "merge")
      .$type
  )
  .annotate("db.table", "aooth_users")

// prettier-ignore-end