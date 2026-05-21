<script setup lang="ts">
import { RouterLink } from "vue-router";
import { WORKFLOWS } from "../workflows";
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
          :to="{ name: 'wf', query: { id: wf.id } }"
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
      </li>
    </ul>
  </div>
</template>
