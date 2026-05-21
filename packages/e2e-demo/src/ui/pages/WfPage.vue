<script setup lang="ts">
import { computed, ref } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import { AsWfForm } from "@atscript/vue-wf";
import { createDefaultTypes } from "@atscript/vue-form";
import { useHydrated } from "../composables/useHydrated";
import { WORKFLOWS } from "../workflows";

const route = useRoute();
const router = useRouter();
const wfId = computed(() => {
  const raw = route.query.id;
  return typeof raw === "string" ? raw : null;
});
const descriptor = computed(() => WORKFLOWS.find((w) => w.id === wfId.value) ?? null);

const hydrated = useHydrated();
const types = createDefaultTypes();

const finished = ref<unknown>(null);
const error = ref<string | null>(null);

function onFinished(result: unknown): void {
  finished.value = result;
  error.value = null;
}

function onError(err: { message?: string }): void {
  error.value = err?.message ?? "Workflow failed";
  finished.value = null;
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

      <div class="card layer-3 p-$l">
        <AsWfForm
          v-if="hydrated"
          :key="wfId"
          path="/auth/trigger"
          :name="wfId"
          :types="types"
          :navigate="navigate"
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
            </div>
            <p class="text-xs text-current-muted mt-$xs">{{ cred.notes }}</p>
          </li>
        </ul>
      </section>
    </template>
  </div>
</template>
