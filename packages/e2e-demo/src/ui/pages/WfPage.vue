<script setup lang="ts">
import { computed, ref } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import { AsWfFinish, AsWfForm, type WfFinished } from "@atscript/vue-wf";
import { createDefaultTypes } from "@atscript/vue-form";
import { AsConsentArray, AsPasswordRules, AsQrCode, AsSsoProviders } from "@atscript/vue-aooth";
import { useHydrated } from "../composables/useHydrated";
import { WORKFLOWS } from "../workflows";

const route = useRoute();
const router = useRouter();
const wfId = computed(() => {
  const raw = route.query.id;
  return typeof raw === "string" ? raw : null;
});
const variant = computed(() => {
  const raw = route.query.variant;
  return typeof raw === "string" && raw.length > 0 ? raw : null;
});
// Magic-link / pincode-link resume token. `auth.recovery` and `auth.invite`
// finish their first leg by emailing a URL like `/recover?wfs=<token>`; the
// router rewrites that into `/wf?id=auth.recovery&wfs=<token>`. AsWfForm
// honours `initialToken` to skip the kickoff POST and resume the paused state.
const initialToken = computed(() => {
  const raw = route.query.wfs;
  return typeof raw === "string" && raw.length > 0 ? raw : undefined;
});
const descriptor = computed(() => WORKFLOWS.find((w) => w.id === wfId.value) ?? null);
// Variant travels via header → server picks the preset in the workflow
// controller constructor. Re-keying on `wfId + variant` forces `<AsWfForm>` to
// remount when the user switches variant mid-page, so the next request hits a
// freshly-constructed (and freshly-merged) workflow controller.
const formKey = computed(() => `${wfId.value}:${variant.value ?? ""}`);

// Demo session: the bundled login finish returns `data.accessToken` in the
// body (the demo SPA is otherwise cookieless — see `onFinished`). We stash it in
// sessionStorage and replay it as `Authorization: Bearer` so GUARDED triggers
// (the change-password flow is the only non-`@Public` one) pass the auth guard,
// which has `enableBearer` on by default. Public flows ignore it harmlessly.
const DEMO_TOKEN_KEY = "aooth_demo_access_token";
function readDemoToken(): string | undefined {
  if (typeof sessionStorage === "undefined") return undefined;
  return sessionStorage.getItem(DEMO_TOKEN_KEY) ?? undefined;
}
const fetchOptions = computed(() => {
  const headers: Record<string, string> = {};
  if (variant.value) headers["x-wf-variant"] = variant.value;
  const token = readDemoToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return Object.keys(headers).length > 0 ? { headers } : undefined;
});

const hydrated = useHydrated();
const types = createDefaultTypes();
// Custom carrier-form components registered via `<AsWfForm :components>` →
// `<AsForm :components>`. `AsConsentArray` (from `@atscript/vue-aooth`) is
// the renderer for the `WithInlineConsentForm.consents: string[]` field —
// it self-hides when `ctx.consents.pending` is empty. `AsPasswordRules`
// renders the live password-policy fulfillment readout on
// `SetPasswordForm.passwordRules` — its `policies` attr binds to
// `ctx.password.policies` (Phase 7) and its `password` attr re-reads
// `data.newPassword` on every keystroke so each row's `data-passed` flag
// reflects the current input value. `AsSsoProviders` is the one-click SSO
// picker for `LoginCredentialsForm.ssoProvider` — it reads the provider list
// from `ctx.public.altActions.ssoProviders` (via the field's `providers` attr)
// and self-hides when none are configured.
const components = { AsConsentArray, AsPasswordRules, AsQrCode, AsSsoProviders };

const finished = ref<unknown>(null);
const error = ref<string | null>(null);
const formHost = ref<HTMLElement | null>(null);
// `idempotentEnvelope` paints the 2-button finish for the invite re-click
// fallback (WF-INVITE-010). Kept separate from `finished` because that one
// emits an arbitrary unknown JSON to a `<pre>`, while this one is a typed
// `WfFinished` we hand straight to `<AsWfFinish>` for envelope-shape parity
// with the wire path.
const idempotentEnvelope = ref<WfFinished | null>(null);

function onFinished(result: unknown): void {
  finished.value = result;
  error.value = null;
  idempotentEnvelope.value = null;
  // Persist the access token from any finish that issues one (login, recovery
  // auto-login, change-password rotation) so subsequent guarded triggers
  // authenticate. See `fetchOptions` for the replay side.
  const token = (result as { data?: { accessToken?: unknown } } | null)?.data?.accessToken;
  if (typeof token === "string" && token.length > 0 && typeof sessionStorage !== "undefined") {
    sessionStorage.setItem(DEMO_TOKEN_KEY, token);
  }
}

async function onError(err: { message?: string }): Promise<void> {
  // Invite re-click after redemption: the wf state store returns 410 (the
  // workflow can't re-enter `inviteCheckPendingInvitation`). The magic-link
  // URL has a `&uid=…` we can use to ask the side route for the same
  // idempotent envelope the workflow would have rendered. Gate on `uid`
  // being present so non-invite 410s (recovery short-TTL, etc.) keep their
  // existing error UX.
  const uidRaw = route.query.uid;
  const uid = typeof uidRaw === "string" && uidRaw.length > 0 ? uidRaw : null;
  if (uid) {
    try {
      const res = await fetch(`/auth/invite/post-redemption?uid=${encodeURIComponent(uid)}`, {
        credentials: "include",
      });
      if (res.ok) {
        const envelope = (await res.json()) as WfFinished;
        idempotentEnvelope.value = envelope;
        error.value = null;
        finished.value = null;
        return;
      }
    } catch {
      // Network/parse failure → fall through to the plain error UI below.
    }
  }
  error.value = err?.message ?? "Workflow failed";
  finished.value = null;
  idempotentEnvelope.value = null;
}

// Demo helper: synthesize an `input` event on the rendered field so Vue's
// v-model picks the value up and writes it back into the reactive formData.
// Using the native setter is the standard workaround for triggering framework
// listeners from outside the framework (React/Vue both rely on the event).
function fillField(name: string, value: string): boolean {
  const root = formHost.value;
  if (!root) return false;
  const el = root.querySelector(`[name="${name}"]`) as
    | HTMLInputElement
    | HTMLTextAreaElement
    | null;
  if (!el) return false;
  const proto =
    el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
  setter?.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  return true;
}

function applyCreds(cred: { username: string; password: string }): void {
  const ok = fillField("username", cred.username) && fillField("password", cred.password);
  if (!ok) {
    // Likely on a later workflow step where these fields aren't present.
    // No-op rather than throw — the panel stays useful across steps.
  }
}

// Drives `AsWfForm.navigate` — workflows finishing with a redirect action
// (e.g. `forgotPassword` → `/wf?id=auth.recovery`) call this. Internal routes
// stay inside the SPA via vue-router; external URLs hand off to the browser.
async function navigate(url: string): Promise<void> {
  if (url.startsWith("/")) {
    await router.push(url);
  } else {
    window.location.href = url;
  }
}
</script>

<template>
  <div class="max-w-2xl mx-auto py-$xl">
    <RouterLink to="/" class="text-sm text-current-muted hover:text-current">
      ← back to workflows
    </RouterLink>

    <div v-if="!wfId" class="mt-$l scope-error">
      Missing <code>?id=</code> query — pick a workflow from
      <RouterLink to="/">the home page</RouterLink>.
    </div>

    <template v-else>
      <h1 class="text-h2 mt-$s mb-$xs">{{ descriptor?.label ?? wfId }}</h1>
      <p v-if="descriptor" class="text-sm text-current-muted mb-$l">
        <code>{{ wfId }}</code> — {{ descriptor.description }}
      </p>
      <p v-else class="text-sm scope-warn mb-$l">
        Unknown workflow id <code>{{ wfId }}</code> (not in WORKFLOWS list).
      </p>

      <div v-if="error" class="scope-error mb-$m border-l-2 border-current pl-$s py-$xs">
        {{ error }}
      </div>

      <div v-if="finished" class="scope-good mb-$m border-l-2 border-current pl-$s py-$xs">
        <strong>Workflow finished.</strong>
        <pre class="text-xs mt-$xs whitespace-pre-wrap">{{
          JSON.stringify(finished, null, 2)
        }}</pre>
      </div>

      <div ref="formHost" class="card layer-3 p-$l">
        <AsWfFinish v-if="idempotentEnvelope" :payload="idempotentEnvelope" :navigate="navigate" />
        <AsWfForm
          v-else-if="hydrated"
          :key="formKey"
          :path="descriptor?.endpoint ?? '/auth/trigger'"
          :name="wfId"
          :types="types"
          :components="components"
          :navigate="navigate"
          :fetch-options="fetchOptions"
          :initial-token="initialToken"
          @finished="onFinished"
          @error="onError"
        />
        <p v-else class="text-sm text-current-muted">Preparing form…</p>
      </div>

      <section v-if="descriptor?.testCreds?.length" class="mt-$l">
        <h2 class="text-h5 mb-$xs">Test credentials</h2>
        <p class="text-xs text-current-muted mb-$s">
          All seeded users — pick one to drive the branch you want to exercise. OTP codes (email /
          SMS) and TOTP secrets are emitted to the dev server console (the terminal running
          <code>pnpm run dev</code>).
        </p>
        <ul class="flex flex-col gap-$xs">
          <li
            v-for="cred in descriptor.testCreds"
            :key="cred.username"
            class="layer-4 rounded-r0 p-$s text-sm"
          >
            <div class="flex flex-wrap items-center gap-$s">
              <code class="font-mono">{{ cred.username }}</code>
              <span class="text-current-muted">/</span>
              <code class="font-mono">{{ cred.password }}</code>
              <button
                type="button"
                class="ml-auto text-xs scope-good px-$s py-$xs rounded-r0 border-1 border-current hover:layer-5"
                title="Fill username & password into the form"
                @click="applyCreds(cred)"
              >
                Fill
              </button>
            </div>
            <p class="text-xs text-current-muted mt-$xs">{{ cred.notes }}</p>
          </li>
        </ul>
      </section>
    </template>
  </div>
</template>
