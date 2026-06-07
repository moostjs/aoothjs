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
 * `<AsWfForm>` only EMITS `action` (it never exposes an imperative
 * `action()`), and the AsForm slot bag has no `invokeAction`, so a host
 * button can't fire a workflow action through the component. The supported
 * way is the headless `useWfForm()` engine, whose `action(name)` does the
 * trigger round-trip. This component is that minimal headless shell — it
 * mirrors `<AsWfForm>`'s own composition (useWfForm + AsForm + AsWfFinish)
 * and adds the host Cancel button.
 *
 * It is wired in for descriptors flagged `hostCancel` (see `workflows.ts`);
 * every other flow keeps using `<AsWfForm>` in `WfPage.vue`.
 */
import { computed, toRaw, watch } from "vue";
import { AsForm } from "@atscript/vue-form";
import { AsWfFinish, useWfForm } from "@atscript/vue-wf";
import type { Component } from "vue";

const props = defineProps<{
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
  /** Finish-screen navigation policy (forwarded to AsWfFinish). */
  navigate?: (url: string) => void | Promise<void>;
}>();

const emit = defineEmits<{
  (e: "finished", result: unknown): void;
  (e: "error", err: { message?: string }): void;
}>();

const {
  formDef,
  formData,
  formContext,
  formKey,
  errors,
  loading,
  finished,
  finishedPayload,
  response,
  error,
  submit,
  action,
} = useWfForm({
  path: props.path,
  name: props.name,
  fetchOptions: props.fetchOptions,
  autoStart: true,
});

// Forward the same host event surface `<AsWfForm>` emits, so `WfPage.vue`'s
// existing `@finished` / `@error` handlers (finish <pre> + error block) work
// unchanged regardless of which shell rendered the flow.
watch(finished, (done) => {
  if (done) emit("finished", response.value);
});
// Normalize the wf error (string | { message }) to its text, shared by the
// host `@error` emit and the inline display below.
function messageOf(e: unknown): string | undefined {
  return typeof e === "string" ? e : (e as { message?: string } | null)?.message;
}

watch(error, (err) => {
  if (!err) return;
  emit("error", { message: messageOf(err) });
});

// Surface the host Cancel ONLY on steps that actually declare a `cancel`
// action (the menu + enrol / remove / password-reauth forms). The reused
// login step-up challenge forms (MfaCodeForm / PincodeForm / Select2faForm)
// do NOT whitelist `cancel`, so firing it there would be rejected server-side
// — gate on the form def to never render a dead button.
const canCancel = computed(() => (formDef.value?.fields ?? []).some((f) => f.name === "cancel"));

// Inline error copy (mirrors AsWfForm's `wf.error.value?.message ?? "Error"`).
// Only rendered while `error` is truthy (see the template's `v-if="error"`).
const errorMessage = computed(() => messageOf(error.value) ?? "Error");

function onSubmit(data: unknown): void {
  submit(toRaw(data));
}

// None of the manage-MFA forms carry a `@wf.action.withData` action (only
// login's forgotPassword/sso do), so a plain `action(name)` is correct here.
// A flow that adds data-carrying actions would mirror AsWfForm's
// withDataActions split.
function onAction(name: string): void {
  action(name);
}

function cancel(): void {
  action("cancel");
}
</script>

<template>
  <div>
    <AsWfFinish v-if="finished" :payload="finishedPayload" :navigate="navigate" />
    <template v-else-if="formDef && formData">
      <!-- Mirror <AsWfForm>: a server/step error renders inline above the form
           (WfPage also surfaces it via @error). Field-level validation errors
           are owned by AsForm per-field. -->
      <div v-if="error" class="scope-error mb-$s">{{ errorMessage }}</div>
      <AsForm
        :key="formKey"
        :def="formDef"
        :form-data="formData"
        :form-context="formContext"
        :types="types"
        :components="components"
        :errors="errors"
        :loading="loading"
        @submit="onSubmit"
        @action="onAction"
        @unsupported-action="onAction"
      />
      <!-- Host-owned Cancel (see component doc). `type="button"` keeps it out
           of the form's submit path (the e2e `submitForm` targets the AsForm
           submit button, not this one). -->
      <button
        v-if="canCancel"
        type="button"
        class="wf-host-cancel mt-$s text-sm text-current-muted hover:text-current underline"
        @click="cancel"
      >
        Cancel
      </button>
    </template>
    <p v-else class="text-sm text-current-muted">Preparing form…</p>
  </div>
</template>
