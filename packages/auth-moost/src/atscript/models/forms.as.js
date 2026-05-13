// prettier-ignore-start
/* eslint-disable */
/* oxlint-disable */
import { defineAnnotatedType as $, annotate as $a, throwFeatureDisabled as $d } from "@atscript/typescript/utils"

export class LoginCredentialsForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "LoginCredentialsForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class MfaCodeForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "MfaCodeForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class EmailIdentifierForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "EmailIdentifierForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class SetPasswordForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "SetPasswordForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class InviteForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "InviteForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}

$("object", LoginCredentialsForm)
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
      .$type
  )

$("object", MfaCodeForm)
  .prop(
    "code",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Verification code")
      .annotate("ui.form.autocomplete", "one-time-code")
      .annotate("meta.required", { })
      .annotate("expect.minLength", { length: 4,  })
      .annotate("expect.maxLength", { length: 12,  })
      .annotate("expect.pattern", { pattern: "^[0-9]+$",  }, true)
      .$type
  )

$("object", EmailIdentifierForm)
  .prop(
    "email",
    $().designType("string")
      .tags("email", "string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Email")
      .annotate("ui.form.autocomplete", "email")
      .annotate("meta.required", { })
      .annotate("expect.pattern", { pattern: "^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$",  flags: "",  message: "Invalid email format." }, true)
      .$type
  )

$("object", SetPasswordForm)
  .prop(
    "newPassword",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "password")
      .annotate("meta.label", "New password")
      .annotate("ui.form.autocomplete", "new-password")
      .annotate("meta.sensitive", true)
      .annotate("meta.required", { })
      .annotate("expect.minLength", { length: 8,  })
      .$type
  ).prop(
    "confirmPassword",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "password")
      .annotate("meta.label", "Confirm password")
      .annotate("ui.form.autocomplete", "new-password")
      .annotate("meta.sensitive", true)
      .annotate("meta.required", { })
      .annotate("expect.minLength", { length: 8,  })
      .$type
  )

$("object", InviteForm)
  .prop(
    "email",
    $().designType("string")
      .tags("email", "string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Email")
      .annotate("ui.form.autocomplete", "email")
      .annotate("meta.required", { })
      .annotate("expect.pattern", { pattern: "^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$",  flags: "",  message: "Invalid email format." }, true)
      .$type
  ).prop(
    "roles",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Roles (comma-separated, optional)")
      .annotate("ui.form.placeholder", "admin,editor")
      .optional()
      .$type
  )

// prettier-ignore-end