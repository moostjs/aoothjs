<script setup lang="ts">
import { ref } from "vue";
import { RouterLink } from "vue-router";
import { INVITE_VARIANTS, LOGIN_VARIANTS, RECOVERY_VARIANTS } from "../../variants";
import { WORKFLOWS } from "../workflows";

// Map each workflow id to the names of its registered variant presets so the
// dropdown only surfaces options the backend will actually merge.
const VARIANTS_BY_WF: Record<string, string[]> = {
  "auth/login/flow": Object.keys(LOGIN_VARIANTS),
  "auth/recovery/flow": Object.keys(RECOVERY_VARIANTS),
  "auth/invite/start": Object.keys(INVITE_VARIANTS),
  "auth/invite/resend": Object.keys(INVITE_VARIANTS),
  "auth/invite/cancel": Object.keys(INVITE_VARIANTS),
};

// Per-row selection — keyed by wf id so each row remembers its own pick.
const selectedVariant = ref<Record<string, string>>({});
</script>

<template>
  <div class="max-w-3xl mx-auto py-$xl">
    <h1 class="text-h1 mb-$s">aooth e2e-demo</h1>
    <p class="text-current-muted mb-$xl">
      Manual test harness — pick a workflow to drive end-to-end.
    </p>

    <ul class="flex flex-col gap-$s">
      <li v-for="wf in WORKFLOWS" :key="wf.id">
        <RouterLink
          :to="{
            name: 'wf',
            query: selectedVariant[wf.id]
              ? { id: wf.id, variant: selectedVariant[wf.id] }
              : { id: wf.id },
          }"
          class="card layer-3 hover:layer-4 transition-colors block p-$m no-underline"
        >
          <div class="flex items-center justify-between gap-$s">
            <strong class="text-current">{{ wf.label }}</strong>
            <span
              v-if="wf.requiresAuth"
              class="text-xs scope-warn text-current-muted px-$xs rounded-r0 layer-4"
            >
              requires auth
            </span>
          </div>
          <p class="text-sm text-current-muted mt-$xs">
            <code>{{ wf.id }}</code> — {{ wf.description }}
          </p>
        </RouterLink>
        <div v-if="VARIANTS_BY_WF[wf.id]" class="mt-$xs flex items-center gap-$xs text-xs">
          <label :for="`variant-${wf.id}`" class="text-current-muted">variant:</label>
          <select
            :id="`variant-${wf.id}`"
            v-model="selectedVariant[wf.id]"
            class="layer-4 text-xs px-$xs py-$xs rounded-r0"
          >
            <option value="">(default)</option>
            <option v-for="name in VARIANTS_BY_WF[wf.id]" :key="name" :value="name">
              {{ name }}
            </option>
          </select>
        </div>
      </li>
    </ul>
  </div>
</template>
