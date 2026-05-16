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


export class BackupCodeForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "BackupCodeForm"
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


export class Select2faForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "Select2faForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class PincodeForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "PincodeForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class AskEmailForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "AskEmailForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class AskPhoneForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "AskPhoneForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class TermsAcceptForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "TermsAcceptForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class ProfileCompleteForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "ProfileCompleteForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class ConsentMarketingForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "ConsentMarketingForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class TenantSelectForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "TenantSelectForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class PersonaSelectForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "PersonaSelectForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class ConcurrencyLimitForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "ConcurrencyLimitForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class MagicLinkRequestForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "MagicLinkRequestForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class RecoveryModeSelectForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "RecoveryModeSelectForm"
  static toJsonSchema() {
    $d("JSON Schema", "jsonSchema", "emit.jsonSchema")
  }
}


export class RecoveryFactorForm {
  static __is_atscript_annotated_type = true
  static type = {}
  static metadata = new Map()
  static id = "RecoveryFactorForm"
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

$("object", BackupCodeForm)
  .prop(
    "code",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Backup code")
      .annotate("ui.form.autocomplete", "one-time-code")
      .annotate("meta.required", { })
      .annotate("expect.minLength", { length: 4,  })
      .annotate("expect.maxLength", { length: 32,  })
      .annotate("expect.pattern", { pattern: "^[A-Z2-9-]+$",  }, true)
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
  .annotate("wf.context.pass", "defaults", true)

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

$("object", Select2faForm)
  .prop(
    "methodName",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "MFA method")
      .annotate("meta.required", { })
      .$type
  ).prop(
    "saveAsDefault",
    $().designType("boolean")
      .tags("boolean")
      .annotate("ui.form.type", "checkbox")
      .annotate("meta.label", "Save as default")
      .optional()
      .$type
  )

$("object", PincodeForm)
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
  ).prop(
    "rememberDevice",
    $().designType("boolean")
      .tags("boolean")
      .annotate("ui.form.type", "checkbox")
      .annotate("meta.label", "Remember this device")
      .optional()
      .$type
  )

$("object", AskEmailForm)
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

$("object", AskPhoneForm)
  .prop(
    "phone",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Phone (E.164)")
      .annotate("ui.form.autocomplete", "tel")
      .annotate("meta.required", { })
      .$type
  )

$("object", TermsAcceptForm)
  .prop(
    "acceptedVersion",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Accepted version")
      .annotate("meta.required", { })
      .$type
  ).prop(
    "accepted",
    $().designType("boolean")
      .tags("boolean")
      .annotate("ui.form.type", "checkbox")
      .annotate("meta.label", "I accept the Terms & Conditions")
      .annotate("meta.required", { })
      .$type
  )

$("object", ProfileCompleteForm)
  .prop(
    "firstName",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "First name")
      .optional()
      .$type
  ).prop(
    "lastName",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Last name")
      .optional()
      .$type
  )

$("object", ConsentMarketingForm)
  .prop(
    "optIn",
    $().designType("boolean")
      .tags("boolean")
      .annotate("ui.form.type", "checkbox")
      .annotate("meta.label", "I would like to receive marketing emails")
      .optional()
      .$type
  )

$("object", TenantSelectForm)
  .prop(
    "tenantId",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Tenant")
      .annotate("meta.required", { })
      .$type
  )

$("object", PersonaSelectForm)
  .prop(
    "personaId",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Persona")
      .annotate("meta.required", { })
      .$type
  )

$("object", ConcurrencyLimitForm)
  .prop(
    "action",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Action")
      .annotate("meta.required", { })
      .annotate("expect.pattern", { pattern: "^(logoutOthers|cancel)$",  }, true)
      .$type
  )

$("object", MagicLinkRequestForm)
  .prop(
    "identifier",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Email or username")
      .annotate("ui.form.autocomplete", "username")
      .annotate("meta.required", { })
      .$type
  )

$("object", RecoveryModeSelectForm)
  .prop(
    "mode",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Recovery method")
      .annotate("meta.required", { })
      .annotate("expect.pattern", { pattern: "^(magicLink|otp)$",  }, true)
      .$type
  )

$("object", RecoveryFactorForm)
  .prop(
    "factor",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Factor")
      .annotate("meta.required", { })
      .annotate("expect.pattern", { pattern: "^(phone|totp)$",  }, true)
      .$type
  ).prop(
    "value",
    $().designType("string")
      .tags("string")
      .annotate("ui.form.type", "text")
      .annotate("meta.label", "Value")
      .annotate("meta.required", { })
      .annotate("expect.minLength", { length: 4,  })
      .annotate("expect.maxLength", { length: 12,  })
      .$type
  )

// prettier-ignore-end