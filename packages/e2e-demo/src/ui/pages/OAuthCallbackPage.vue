<script setup lang="ts">
import { computed, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { AsWfForm } from "@atscript/vue-wf";
import { createDefaultTypes } from "@atscript/vue-form";
import { AsConsentArray, AsPasswordRules, AsQrCode, AsSsoProviders } from "@atscript/vue-aooth";
import { useHydrated } from "../composables/useHydrated";

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
// Same custom-component map as WfPage: a federated login can land on the SAME
// consent / MFA-enrollment / prove-control steps a password login does, so the
// callback's `<AsWfForm>` must register the renderers those forms reference
// (AsConsentArray / AsPasswordRules / AsQrCode) plus AsSsoProviders for parity.
const components = { AsConsentArray, AsPasswordRules, AsQrCode, AsSsoProviders };
const error = ref<string | null>(null);
const finished = ref<unknown>(null);

// Mirror WfPage: the cookieless demo replays this Bearer token for guarded
// triggers. A successful OAuth login finishes with `data.accessToken` (the demo
// opts out of the server-driven redirect — see DemoAuthWorkflow.resolveRedirect).
const DEMO_TOKEN_KEY = "aooth_demo_access_token";

function onFinished(result: unknown): void {
  finished.value = result;
  error.value = null;
  const token = (result as { data?: { accessToken?: unknown } } | null)?.data?.accessToken;
  if (typeof token === "string" && token.length > 0) {
    if (typeof sessionStorage !== "undefined") sessionStorage.setItem(DEMO_TOKEN_KEY, token);
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
        :components="components"
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
