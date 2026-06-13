<script setup lang="ts">
/**
 * Reference "host-rendered Cancel" shell for the manage-MFA flow.
 *
 * WHY THIS EXISTS. The bundled manage-MFA forms (`@aooth/auth-moost`) HIDE
 * their built-in `cancel` action — it stays in each form's action whitelist
 * but `@ui.form.fn.hidden '() => true'` suppresses the default button. The
 * intended consumer pattern is: render your OWN Cancel affordance and dispatch
 * the `cancel` action when the user abandons the flow. That aborts the run
 * server-side (→ the "cancelled" terminal), which lets the durable wf-state
 * row be cleaned up instead of lingering until it expires.
 *
 * Since `@atscript/vue-wf@0.1.101`, `<AsWfForm>` exposes the host-fired action
 * surface on its component instance: `action(name, data?)` fires the action
 * (auto-classifying data-carrying ones via `@wf.action.withData`), and
 * `supportsAction(name)` reports whether the CURRENT step's form declares that
 * action id. So this shell is now a thin wrapper over `<AsWfForm>` — a template
 * ref plus a Cancel button — instead of the hand-rolled headless `useWfForm()`
 * re-implementation it used to be. Every other flow renders `<AsWfForm>`
 * directly in `WfPage.vue`; this one only adds the Cancel affordance.
 *
 * It is wired in for descriptors flagged `hostCancel` (see `workflows.ts`).
 */
import { computed, useTemplateRef } from "vue";
import { AsWfForm } from "@atscript/vue-wf";
import type { Component } from "vue";

defineProps<{
  /** Workflow HTTP endpoint (the guarded `/auth/add-mfa` for manage-MFA). */
  path: string;
  /** Workflow id (`auth/add-mfa/flow`). */
  name: string;
  /** Built-in type → component map (`createDefaultTypes()`). */
  types: Record<string, Component>;
  /** Named-component map for `@ui.form.component` fields (AsQrCode, …). */
  components?: Record<string, Component>;
  /** Per-request fetch options — carries the `Authorization: Bearer` header. */
  fetchOptions?: { headers?: Record<string, string> };
  /** Finish-screen navigation policy (forwarded to AsWfForm). */
  navigate?: (url: string) => void | Promise<void>;
}>();

// Re-emit `<AsWfForm>`'s own events unchanged, so `WfPage.vue`'s existing
// `@finished` / `@error` handlers work the same regardless of which shell
// rendered the flow.
defineEmits<{
  (e: "finished", result: unknown): void;
  (e: "error", err: { message?: string }): void;
}>();

const form = useTemplateRef<{
  action: (name: string, data?: unknown) => void;
  supportsAction: (name: string) => boolean;
}>("form");

// Surface the host Cancel ONLY on steps whose form actually DECLARES a `cancel`
// action — gate on the action ID, never a field name. The reused login step-up
// challenge forms (MfaCodeForm / PincodeForm / Select2faForm) do NOT whitelist
// `cancel`, so firing it there would be rejected server-side; `supportsAction`
// reads the live FormDef, so the button appears / disappears as the flow
// advances step to step.
const canCancel = computed(() => form.value?.supportsAction("cancel") ?? false);

function cancel(): void {
  form.value?.action("cancel");
}
</script>

<template>
  <div>
    <AsWfForm
      ref="form"
      :path="path"
      :name="name"
      :types="types"
      :components="components"
      :navigate="navigate"
      :fetch-options="fetchOptions"
      @finished="(r: unknown) => $emit('finished', r)"
      @error="(e: { message: string }) => $emit('error', e)"
    />
    <!-- Host-owned Cancel (see component doc). `type="button"` keeps it out of
         the form's submit path (the e2e `submitForm` targets the AsForm submit
         button, not this one). -->
    <button
      v-if="canCancel"
      type="button"
      class="wf-host-cancel mt-$s text-sm text-current-muted hover:text-current underline"
      @click="cancel"
    >
      Cancel
    </button>
  </div>
</template>
