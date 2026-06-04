<script setup lang="ts">
import { computed, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { AsWfForm } from "@atscript/vue-wf";
import { createDefaultTypes } from "@atscript/vue-form";
import { useHydrated } from "../composables/useHydrated";
import { writeDemoToken } from "../demoToken";
import { wfFormComponents } from "../wfFormComponents";

// The provider's `redirect_uri` lands the browser here
// (`/auth/oauth/:provider/callback?code=…&state=…`). This page is a thin bridge:
// it forwards `{ code, state }` (or a provider `error`) into the public
// `/auth/trigger` as the START input of `auth/login/flow` (federated login is
// merged into the login workflow: `init-login` sees the inbound `state` and
// routes to `sso-callback` instead of the password form), then renders the
// result with the SAME `<AsWfForm>` the rest of the demo uses — so an MFA /
// consent step that the OAuth login lands on is handled identically to a
// password login. The PKCE verifier never reaches the browser (it is re-derived
// server-side from the signed-state seed); only the single-use `code` does.
const route = useRoute();
const router = useRouter();

const code = computed(() => (typeof route.query.code === "string" ? route.query.code : null));
const state = computed(() => (typeof route.query.state === "string" ? route.query.state : null));
const oauthError = computed(() =>
  typeof route.query.error === "string" ? route.query.error : null,
);

// START input — `<AsWfForm>` wraps this object as `input.formData`, which is
// where `sso-callback` reads `code` / `state` / `error` (the shape every
// aooth form posts). So pass the BARE fields, NOT a nested `{ formData }`.
const startInput = computed(() => ({
  ...(code.value ? { code: code.value } : {}),
  ...(state.value ? { state: state.value } : {}),
  ...(oauthError.value ? { error: oauthError.value } : {}),
}));

const hydrated = useHydrated();
const types = createDefaultTypes();
const error = ref<string | null>(null);
const finished = ref<unknown>(null);

function onFinished(result: unknown): void {
  finished.value = result;
  error.value = null;
  const token = (result as { data?: { accessToken?: unknown } } | null)?.data?.accessToken;
  if (typeof token === "string" && token.length > 0) {
    writeDemoToken(token);
    // Success carries no redirect envelope in the demo → navigate home ourselves.
    void router.push("/");
  }
  // A failure / needs-link finish carries a `next.action` redirect, which
  // `<AsWfForm>` follows through the `navigate` prop below.
}

function onError(err: { message?: string }): void {
  error.value = err?.message ?? "OAuth sign-in failed";
  finished.value = null;
}

async function navigate(url: string): Promise<void> {
  if (url.startsWith("/")) await router.push(url);
  else window.location.href = url;
}
</script>

<template>
  <div class="max-w-2xl mx-auto py-$xl" data-testid="oauth-callback">
    <h1 class="text-h2 mb-$l">Signing you in…</h1>

    <div
      v-if="error"
      class="scope-error mb-$m border-l-2 border-current pl-$s py-$xs"
      data-testid="oauth-error"
    >
      {{ error }}
    </div>

    <div
      v-if="finished"
      class="scope-good mb-$m border-l-2 border-current pl-$s py-$xs"
      data-testid="oauth-finished"
    >
      <strong>Signed in.</strong>
      <pre class="text-xs mt-$xs whitespace-pre-wrap">{{ JSON.stringify(finished, null, 2) }}</pre>
    </div>

    <div class="card layer-3 p-$l">
      <AsWfForm
        v-if="hydrated && (code || oauthError)"
        name="auth/login/flow"
        path="/auth/trigger"
        :types="types"
        :components="wfFormComponents"
        :input="startInput"
        :navigate="navigate"
        @finished="onFinished"
        @error="onError"
      />
      <p v-else-if="!code && !oauthError" class="scope-error">
        Missing OAuth callback parameters (<code>code</code> / <code>state</code>).
      </p>
      <p v-else class="text-sm text-current-muted">Preparing…</p>
    </div>
  </div>
</template>
