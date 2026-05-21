// prettier-ignore-start
/* eslint-disable */
/* oxlint-disable */
import { defineAnnotatedType as $, annotate as $a, throwFeatureDisabled as $d } from "@atscript/typescript/utils"

export class SsoLoginCredentialsForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "SsoLoginCredentialsForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}

$("object", SsoLoginCredentialsForm)
  .prop(
    "username",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Username")
      .annotate("ui.form.autocomplete", "username")
      .annotate("meta.required", { })
      .annotate("expect.minLength", { length: 1,  })
      .$type
  ).prop(
    "password",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "password")
      .annotate("meta.label", "Password")
      .annotate("ui.form.autocomplete", "current-password")
      .annotate("meta.sensitive", true)
      .annotate("meta.required", { })
      .annotate("expect.minLength", { length: 1,  })
      .annotate("ui.form.action", { id: "forgotPassword",  label: "Forgot password?" })
      .annotate("wf.action.withData", "forgotPassword")
      .$type
  ).prop(
    "signup",
    $().designType("phantom")
      .tags("action", "ui")
      .annotate("ui.form.action", { id: "signup",  label: "Sign up" })
      .optional()
      .$type
  ).prop(
    "magicLink",
    $().designType("phantom")
      .tags("action", "ui")
      .annotate("ui.form.action", { id: "magicLink",  label: "Sign in with a magic link" })
      .optional()
      .$type
  ).prop(
    "google",
    $().designType("phantom")
      .tags("action", "ui")
      .annotate("ui.form.action", { id: "google",  label: "Sign in with Google" })
      .optional()
      .$type
  ).prop(
    "okta",
    $().designType("phantom")
      .tags("action", "ui")
      .annotate("ui.form.action", { id: "okta",  label: "Sign in with Okta" })
      .optional()
      .$type
  )

// prettier-ignore-end