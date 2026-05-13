// prettier-ignore-start
/* eslint-disable */
/* oxlint-disable */
import { defineAnnotatedType as $, annotate as $a, throwFeatureDisabled as $d } from "@atscript/typescript/utils"

export class TestUser {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "TestUser"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class TestUserOverride {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "TestUserOverride"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}

$("object", TestUser)
  .prop(
    "id",
    $().designType("string")
      .tags("string")
      .annotate("meta.id", true)
      .$type
  ).prop(
    "username",
    $().designType("string")
      .tags("string")
      .$type
  ).prop(
    "roles",
    $("array")
      .of($().designType("string")
          .tags("string")
          .$type)
      .annotate("arbac.role", true)
      .$type
  ).prop(
    "extraRoles",
    $("array")
      .of($().designType("string")
          .tags("string")
          .$type)
      .annotate("arbac.role", true)
      .$type
  ).prop(
    "tenantId",
    $().designType("string")
      .tags("string")
      .annotate("arbac.attribute", true)
      .$type
  ).prop(
    "department",
    $().designType("string")
      .tags("string")
      .annotate("arbac.attribute", true)
      .$type
  ).prop(
    "secret",
    $().designType("string")
      .tags("string")
      .$type
  )
  .annotate("db.table", "test_users")

$("object", TestUserOverride)
  .prop(
    "id",
    $().designType("string")
      .tags("string")
      .annotate("meta.id", true)
      .$type
  ).prop(
    "externalId",
    $().designType("string")
      .tags("string")
      .annotate("arbac.userId", true)
      .$type
  ).prop(
    "role",
    $().designType("string")
      .tags("string")
      .annotate("arbac.role", true)
      .$type
  ).prop(
    "tenantId",
    $().designType("string")
      .tags("string")
      .annotate("arbac.attribute", true)
      .$type
  )
  .annotate("db.table", "test_users_override")

// prettier-ignore-end