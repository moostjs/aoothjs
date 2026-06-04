<script setup lang="ts">
import { onMounted, ref } from "vue";
import { RouterLink } from "vue-router";
import type { ConnectedAccount } from "@aooth/auth-moost";
import { useHydrated } from "../composables/useHydrated";

// Cookieless demo: the bundled login finish returns `data.accessToken`, which
// WfPage / OAuthCallbackPage stash in sessionStorage and replay as a Bearer for
// guarded routes. The connected-accounts routes (`GET /auth/oauth/identities`,
// `DELETE /auth/oauth/:provider/:subject`) are self-scoped, so they need it.
const DEMO_TOKEN_KEY = "aooth_demo_access_token";
function readToken(): string | null {
  return typeof sessionStorage === "undefined" ? null : sessionStorage.getItem(DEMO_TOKEN_KEY);
}

const hydrated = useHydrated();
const authed = ref(false);
const loading = ref(false);
const accounts = ref<ConnectedAccount[] | null>(null);
const error = ref<string | null>(null);

async function load(): Promise<void> {
  const token = readToken();
  if (!token) {
    authed.value = false;
    return;
  }
  authed.value = true;
  loading.value = true;
  error.value = null;
  try {
    const res = await fetch("/auth/oauth/identities", {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.status === 401) {
      // Session ended (e.g. an unlink elsewhere revoked it) — treat as signed out.
      authed.value = false;
      accounts.value = null;
      return;
    }
    if (!res.ok) throw new Error(`Could not load connected accounts (${res.status})`);
    accounts.value = (await res.json()) as ConnectedAccount[];
  } catch (err) {
    error.value = (err as Error).message ?? "Could not load connected accounts";
  } finally {
    loading.value = false;
  }
}

async function unlink(account: ConnectedAccount): Promise<void> {
  const token = readToken();
  if (!token) return;
  error.value = null;
  const res = await fetch(
    `/auth/oauth/${encodeURIComponent(account.provider)}/${encodeURIComponent(account.subject)}`,
    { method: "DELETE", headers: { Authorization: `Bearer ${token}` } },
  );
  if (res.ok) {
    // Optimistic local removal: a successful unlink revokes the user's sessions
    // (one may have been established through the identity just removed), so the
    // stashed Bearer is now stale — re-fetching would 401. Drop the row instead.
    accounts.value = (accounts.value ?? []).filter(
      (a) => !(a.provider === account.provider && a.subject === account.subject),
    );
    return;
  }
  // Surface the server guard inline (e.g. 409 "only sign-in method", 404).
  const body = (await res.json().catch(() => null)) as { message?: string } | null;
  error.value = body?.message ?? `Could not unlink ${account.provider} (${res.status})`;
}

function linkedOn(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

onMounted(() => {
  authed.value = !!readToken();
  if (authed.value) void load();
});
</script>

<template>
  <div class="max-w-2xl mx-auto py-$xl" data-testid="connected-accounts">
    <RouterLink to="/" class="text-sm text-current-muted hover:text-current">
      ← back to workflows
    </RouterLink>
    <h1 class="text-h2 mt-$s mb-$xs">Connected accounts</h1>
    <p class="text-sm text-current-muted mb-$l">
      External sign-in providers linked to your account. Disconnect one to revoke its access — you
      keep any other sign-in method.
    </p>

    <div
      v-if="error"
      class="scope-error mb-$m border-l-2 border-current pl-$s py-$xs"
      data-testid="ca-error"
    >
      {{ error }}
    </div>

    <p v-if="!hydrated" class="text-sm text-current-muted">Loading…</p>
    <p v-else-if="!authed" class="text-sm text-current-muted" data-testid="ca-unauth">
      <RouterLink to="/login">Sign in</RouterLink> to view your connected accounts.
    </p>
    <p v-else-if="loading || accounts === null" class="text-sm text-current-muted">Loading…</p>
    <p v-else-if="accounts.length === 0" class="text-sm text-current-muted" data-testid="ca-empty">
      No connected accounts.
    </p>
    <ul v-else class="flex flex-col gap-$s">
      <li
        v-for="a in accounts"
        :key="`${a.provider}:${a.subject}`"
        :data-testid="`connected-account-${a.provider}`"
        class="card layer-3 p-$m flex items-center justify-between gap-$s"
      >
        <div>
          <strong class="text-current capitalize">{{ a.provider }}</strong>
          <p class="text-xs text-current-muted mt-$xs">
            <span v-if="a.displayName || a.email">{{ a.displayName ?? a.email }} · </span>
            linked {{ linkedOn(a.linkedAt) }}
          </p>
        </div>
        <button
          type="button"
          class="text-xs scope-error px-$s py-$xs rounded-r0 border-1 border-current hover:layer-5"
          @click="unlink(a)"
        >
          Unlink
        </button>
      </li>
    </ul>
  </div>
</template>
