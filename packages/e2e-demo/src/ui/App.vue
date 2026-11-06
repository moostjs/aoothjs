<script setup lang="ts">
import { provideAsLocale } from "@atscript/vue-form";
import { useRoute } from "vue-router";

// The forms' language: a BCP 47-shaped `?lang=` (it becomes a header), else the
// browser's. `<AsWfForm>` sends it as `Accept-Language` and merges the served
// `$i18n`; the server (src/i18n.ts) answers `de` or else English.
const LANG_TAG = /^[A-Za-z]{2,3}(-[A-Za-z0-9]{1,8})*$/;
const route = useRoute();
provideAsLocale(() => {
  const lang = route.query.lang;
  return typeof lang === "string" && LANG_TAG.test(lang) ? lang : globalThis.navigator?.language;
});
</script>

<template>
  <div class="min-h-screen layer-2 p-$l">
    <RouterView />
  </div>
</template>
