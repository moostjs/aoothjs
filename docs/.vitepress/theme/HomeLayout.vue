<script setup>
import { onMounted, nextTick, watch, computed, ref } from "vue";
import { useData, useRoute } from "vitepress";
import DefaultTheme from "vitepress/theme";
import VPButton from "vitepress/dist/client/theme-default/components/VPButton.vue";
import AuthFlowBg from "./AuthFlowBg.vue";
import SnippetUser from "./snippets/snippet-user.md";
import SnippetArbac from "./snippets/snippet-arbac.md";
import SnippetAuth from "./snippets/snippet-auth.md";
import SnippetMoost from "./snippets/snippet-moost.md";

const { Layout } = DefaultTheme;
const { frontmatter } = useData();
const route = useRoute();

const copiedCmd = ref("");
let copyTimer;
async function copyCmd(cmd) {
  try {
    await navigator.clipboard.writeText(cmd);
    copiedCmd.value = cmd;
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => {
      copiedCmd.value = "";
    }, 1400);
  } catch {
    // ignore — clipboard may be unavailable in private contexts
  }
}

const INSTALL_SKILL = "npx skills add moostjs/aoothjs";

function setupScrollAnimations() {
  nextTick(() => {
    if (typeof window === "undefined") return;
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add("visible");
            observer.unobserve(e.target);
          }
        });
      },
      { threshold: 0.12 },
    );
    document.querySelectorAll(".animate-in").forEach((el) => {
      el.classList.remove("visible");
      observer.observe(el);
    });
  });
}

onMounted(() => {
  setupScrollAnimations();
});

watch(
  () => route.path,
  () => {
    setupScrollAnimations();
  },
);

const showcases = computed(() => [
  {
    num: "01",
    eyebrow: "Credentials",
    title: "Built to hold up under scrutiny",
    body: "Scrypt with self-describing hashes, salt + pepper, history checks. Password policies expressed as serializable rules — same predicate runs on server and client. TOTP, backup codes, trusted devices. All behind a pluggable store.",
    tags: ["scrypt", "@prostojs/ftring", "TOTP", "backup codes", "lockout"],
    link: "/user/",
    linkText: "Explore @aooth/user",
    snippet: SnippetUser,
    align: "left",
  },
  {
    num: "02",
    eyebrow: "Authorization",
    title: "Authorization that reaches into the data",
    body: "Roles + privileges + dynamic scopes. Wildcard matchers (* single-segment, ** any depth), deny-wins evaluation. Each allow rule can return a SQL or Mongo filter — a single grant narrows queries automatically. Multi-role unions merge to $in or $or.",
    tags: ["defineRole", "allowTableRead", "mergeScopeFilters", "ControlGate", "ArbacDbScope"],
    link: "/arbac/",
    linkText: "Explore @aooth/arbac",
    snippet: SnippetArbac,
    align: "right",
  },
  {
    num: "03",
    eyebrow: "Auth methods",
    title: "One orchestrator, every credential mode",
    body: "Stateful or stateless — same API. JWT via jose, encapsulated AES-256-GCM, in-memory, Redis, atscript-db. Sliding refresh with grace window and reuse detection. Magic links with atomic single-use guarantees. Per-user epoch revocation.",
    tags: ["AuthCredential", "JWT", "sliding refresh", "magic links", "Redis"],
    link: "/auth/",
    linkText: "Explore @aooth/auth",
    snippet: SnippetAuth,
    align: "left",
  },
  {
    num: "04",
    eyebrow: "Moost integration",
    title: "Decorators, workflows, controllers — declared, not assembled",
    body: "AuthGuard interceptor, useAuth and useArbac composables, an AuthController with a single /trigger entry-point covering three batteries-included workflows: login, recovery, invite. Each pauses for forms and emits a unified WfFinished envelope to the client.",
    tags: ["@Public", "@ArbacAuthorize", "LoginWorkflow", "AsArbacDbController", "WfFinished"],
    link: "/moost/",
    linkText: "Explore @aooth/*-moost",
    snippet: SnippetMoost,
    align: "right",
  },
]);
</script>

<template>
  <Layout>
    <template #home-hero-before>
      <!-- HERO -->
      <section class="aooth-hero">
        <AuthFlowBg />
        <div class="aooth-hero-inner">
          <div class="aooth-hero-pill animate-in">
            <span class="dot" /> v0.1.1 · preview release
          </div>

          <img src="/logo.svg" alt="aooth" class="aooth-wordmark animate-in" />

          <h1 class="aooth-text animate-in">
            Authorization, all the way
            <span class="cyan-underline">to the column</span>
          </h1>

          <p class="aooth-tagline animate-in">
            {{ frontmatter.hero2.tl1 }}
            <strong class="hl-magenta">{{ frontmatter.hero2.tlhl }}</strong>
            {{ frontmatter.hero2.tl2 }}
          </p>

          <div v-if="frontmatter.actions" class="aooth-actions animate-in">
            <div v-for="action in frontmatter.actions" :key="action.link" class="aooth-action">
              <VPButton
                tag="a"
                size="medium"
                :theme="action.theme"
                :text="action.text"
                :href="action.link"
              />
            </div>
          </div>
        </div>
      </section>

      <!-- SHOWCASES -->
      <section
        v-for="(s, i) in showcases"
        :key="s.num"
        class="aooth-showcase"
        :class="[`align-${s.align}`, i % 2 === 1 ? 'bg-soft' : '']"
      >
        <div class="aooth-showcase-inner">
          <div class="showcase-text animate-in">
            <div class="showcase-eyebrow">
              <span class="num">{{ s.num }}</span>
              <span class="dotline" />
              <span class="kicker">{{ s.eyebrow }}</span>
            </div>
            <h2 class="showcase-title">{{ s.title }}</h2>
            <p class="showcase-body">{{ s.body }}</p>
            <div class="showcase-tags">
              <code v-for="t in s.tags" :key="t" class="tag">{{ t }}</code>
            </div>
            <a :href="s.link" class="showcase-link">
              {{ s.linkText }}
              <span class="arrow">→</span>
            </a>
          </div>
          <div class="showcase-snippet animate-in">
            <div class="snippet-frame">
              <div class="snippet-chrome">
                <span class="dot dot-red" />
                <span class="dot dot-amber" />
                <span class="dot dot-green" />
                <span class="snippet-label">{{ s.eyebrow.toLowerCase() }}.ts</span>
              </div>
              <div class="snippet-body">
                <component :is="s.snippet" />
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- AI AGENT SKILL -->
      <section class="aooth-skill">
        <div class="aooth-skill-inner animate-in">
          <div class="skill-head">
            <div class="showcase-eyebrow">
              <span class="num">05</span>
              <span class="dotline" />
              <span class="kicker">AI agent skill</span>
            </div>
            <h2 class="skill-title">Your AI already speaks it</h2>
            <p class="skill-desc">
              One command teaches Claude Code, Cursor, Windsurf, and Codex the entire aoothjs stack
              — <code>UserService</code>, <code>AuthCredential</code>, <code>defineRole</code>,
              <code>AsArbacDbController</code>, the workflow envelope, and the shipped
              <code>.as</code> models.
            </p>
          </div>

          <button
            type="button"
            class="install-card"
            :class="{ copied: copiedCmd === INSTALL_SKILL }"
            :aria-label="`Copy install command: ${INSTALL_SKILL}`"
            @click="copyCmd(INSTALL_SKILL)"
          >
            <span class="install-prompt">$</span>
            <span class="install-cmd">npx skills add <strong>moostjs/aoothjs</strong></span>
            <span class="install-action" aria-hidden="true">
              <span class="install-action-icon">
                <svg
                  v-if="copiedCmd !== INSTALL_SKILL"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <rect x="9" y="9" width="11" height="11" rx="2" />
                  <path d="M5 15V5a2 2 0 0 1 2-2h10" />
                </svg>
                <svg
                  v-else
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2.6"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                >
                  <path d="M5 12.5l4.5 4.5L19 7.5" />
                </svg>
              </span>
              <span class="install-action-label">
                {{ copiedCmd === INSTALL_SKILL ? "Copied!" : "Click to copy" }}
              </span>
            </span>
          </button>

          <ul class="install-bullets">
            <li><span class="bullet-dot" /><code>UserService</code> · password · MFA primitives</li>
            <li>
              <span class="bullet-dot" /><code>defineRole</code> · <code>allowTableRead</code> ·
              scope merging
            </li>
            <li><span class="bullet-dot" /><code>AuthCredential</code> · stores · magic links</li>
            <li><span class="bullet-dot" />Moost guards · workflows · DB controllers</li>
          </ul>

          <a href="https://skills.sh" class="skill-link">
            Learn about AI agent skills
            <span class="arrow">→</span>
          </a>
        </div>
      </section>
    </template>
  </Layout>
</template>

<style scoped>
/* ─────────────────────────────────────────────
 * HERO
 * ───────────────────────────────────────────── */

.aooth-hero {
  position: relative;
  overflow: hidden;
  margin-top: calc((var(--vp-nav-height) + var(--vp-layout-top-height, 0px)) * -1);
  padding: calc(var(--vp-nav-height) + var(--vp-layout-top-height, 0px) + 64px) 24px 96px;
  background: var(--vp-c-bg);
  border-bottom: 1px solid var(--vp-c-divider);
}

.dark .aooth-hero {
  background: linear-gradient(180deg, #0a1722 0%, #0c1d2c 100%);
}

@media (min-width: 640px) {
  .aooth-hero {
    padding-left: 48px;
    padding-right: 48px;
    padding-bottom: 120px;
  }
}

@media (min-width: 960px) {
  .aooth-hero {
    padding-left: 64px;
    padding-right: 64px;
    padding-top: calc(var(--vp-nav-height) + var(--vp-layout-top-height, 0px) + 96px);
    padding-bottom: 140px;
  }
}

.aooth-hero-inner {
  position: relative;
  z-index: 10;
  max-width: 1152px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
}

.aooth-hero-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 6px 14px;
  margin: 0 0 28px;
  font-family: var(--vp-font-family-mono);
  font-size: 12px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--aooth-cyan, #25afdb);
  background: var(--vp-c-brand-soft);
  border: 1px solid rgba(37, 175, 219, 0.32);
  border-radius: 999px;
}

.aooth-hero-pill .dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #db2592;
  box-shadow: 0 0 8px rgba(219, 37, 146, 0.65);
  animation: heroDotPulse 2.6s ease-in-out infinite;
}

@keyframes heroDotPulse {
  0%,
  100% {
    opacity: 1;
    transform: scale(1);
  }
  50% {
    opacity: 0.55;
    transform: scale(1.4);
  }
}

.aooth-wordmark {
  display: block;
  width: clamp(280px, 56vw, 520px);
  height: auto;
  margin: 0 auto 36px;
  filter: drop-shadow(0 12px 32px rgba(37, 175, 219, 0.18));
}

.dark .aooth-wordmark {
  filter: drop-shadow(0 12px 28px rgba(37, 175, 219, 0.28))
    drop-shadow(0 4px 14px rgba(219, 37, 146, 0.12));
}

.aooth-text {
  margin: 0 auto 16px;
  max-width: 760px;
  font-size: 46px;
  line-height: 1.08;
  letter-spacing: -0.02em;
  font-weight: 700;
  color: var(--vp-c-text-1);
  text-wrap: balance;
}

.cyan-underline {
  position: relative;
  white-space: nowrap;
}

.cyan-underline::after {
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  bottom: 2px;
  height: 6px;
  background: rgba(37, 175, 219, 0.22);
  border-radius: 4px;
  z-index: -1;
}

.aooth-tagline {
  margin: 0 auto 36px;
  max-width: 600px;
  font-size: clamp(16px, 1.4vw, 19px);
  line-height: 1.55;
  color: var(--vp-c-text-2);
  text-wrap: balance;
}

.hl-magenta {
  color: #db2592;
  font-weight: 600;
}

.dark .hl-magenta {
  color: #ff5ab5;
}

.aooth-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 12px;
  margin: 0;
}

/* ─────────────────────────────────────────────
 * SHOWCASE SECTIONS
 * ───────────────────────────────────────────── */

.aooth-showcase {
  padding: 96px 24px;
  border-bottom: 1px solid var(--vp-c-divider);
  position: relative;
  overflow: hidden;
}

.aooth-showcase.bg-soft {
  background: var(--vp-c-bg-soft);
}

@media (min-width: 640px) {
  .aooth-showcase {
    padding-left: 48px;
    padding-right: 48px;
  }
}

@media (min-width: 960px) {
  .aooth-showcase {
    padding: 120px 64px;
  }
}

.aooth-showcase-inner {
  max-width: 1152px;
  margin: 0 auto;
  display: grid;
  grid-template-columns: 1fr;
  gap: 56px;
  align-items: start;
}

@media (min-width: 960px) {
  .aooth-showcase-inner {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1.15fr);
    gap: 88px;
  }
  .aooth-showcase.align-right .aooth-showcase-inner {
    grid-template-columns: minmax(0, 1.15fr) minmax(0, 1fr);
  }
  .aooth-showcase.align-right .showcase-text {
    order: 2;
  }
  .aooth-showcase.align-right .showcase-snippet {
    order: 1;
  }
}

.showcase-eyebrow {
  display: flex;
  align-items: center;
  gap: 16px;
  font-family: var(--vp-font-family-mono);
  font-size: 13px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--vp-c-text-2);
  margin-bottom: 20px;
}

.showcase-eyebrow .num {
  color: #db2592;
  font-weight: 600;
}

.dark .showcase-eyebrow .num {
  color: #ff5ab5;
}

.showcase-eyebrow .dotline {
  flex: 0 0 48px;
  height: 1px;
  border-top: 1px dashed currentColor;
  opacity: 0.5;
}

.showcase-eyebrow .kicker {
  color: var(--vp-c-text-1);
  letter-spacing: 0.08em;
}

.showcase-title {
  margin: 0 0 18px;
  font-size: clamp(24px, 2.8vw, 34px);
  line-height: 1.18;
  letter-spacing: -0.015em;
  font-weight: 700;
  color: var(--vp-c-text-1);
}

.showcase-body {
  margin: 0 0 24px;
  font-size: 16px;
  line-height: 1.65;
  color: var(--vp-c-text-2);
}

.showcase-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 28px;
}

.showcase-tags .tag {
  padding: 4px 10px;
  border-radius: 6px;
  font-family: var(--vp-font-family-mono);
  font-size: 12.5px;
  color: var(--vp-c-text-1);
  background: var(--vp-c-bg-elv);
  border: 1px solid var(--vp-c-divider);
}

.showcase-link {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-weight: 600;
  font-size: 15px;
  color: var(--vp-c-brand-1);
  text-decoration: none;
  border-bottom: 1px solid transparent;
  transition:
    border-color 0.2s ease,
    transform 0.2s ease;
}

.showcase-link:hover {
  border-bottom-color: currentColor;
}

.showcase-link .arrow {
  transition: transform 0.25s ease;
}

.showcase-link:hover .arrow {
  transform: translateX(3px);
}

/* ─── snippet frame ─── */

.snippet-frame {
  position: relative;
  border-radius: 12px;
  background: var(--vp-c-bg-elv);
  border: 1px solid var(--vp-c-divider);
  box-shadow:
    0 1px 0 rgba(37, 175, 219, 0.04),
    0 24px 60px -32px rgba(37, 175, 219, 0.22);
  overflow: hidden;
}

.snippet-frame::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: inherit;
  padding: 1px;
  background: linear-gradient(
    140deg,
    rgba(37, 175, 219, 0.32),
    rgba(219, 37, 146, 0.1) 40%,
    transparent 75%
  );
  -webkit-mask:
    linear-gradient(#000 0 0) content-box,
    linear-gradient(#000 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
  pointer-events: none;
  opacity: 0.85;
}

.snippet-chrome {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px;
  background: var(--vp-c-bg-soft);
  border-bottom: 1px solid var(--vp-c-divider);
}

.snippet-chrome .dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--vp-c-text-3);
  opacity: 0.45;
}

.snippet-chrome .dot.dot-red {
  background: #ff6058;
  opacity: 0.85;
}
.snippet-chrome .dot.dot-amber {
  background: #ffbe2e;
  opacity: 0.85;
}
.snippet-chrome .dot.dot-green {
  background: #2bca44;
  opacity: 0.85;
}

.snippet-label {
  margin-left: auto;
  font-family: var(--vp-font-family-mono);
  font-size: 12px;
  color: var(--vp-c-text-2);
}

.snippet-body :deep(div[class*="language-"]) {
  margin: 0;
  border-radius: 0 !important;
  background: var(--vp-c-bg-elv) !important;
  position: relative;
}

/* The custom chrome bar already shows the filename, so hide the inline
 * VitePress lang label and copy button on snippet frames. */
.snippet-body :deep(.lang),
.snippet-body :deep(button.copy) {
  display: none !important;
}

.snippet-body :deep(pre) {
  padding: 18px !important;
  font-size: 13.5px;
  line-height: 1.55;
}

.snippet-body :deep(pre code) {
  display: block;
}

/* ─────────────────────────────────────────────
 * Install card (used by AI skill section)
 * ───────────────────────────────────────────── */

.install-card {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  width: 100%;
  max-width: 520px;
  padding: 12px 12px 12px 18px;
  border-radius: 12px;
  border: 1px solid rgba(37, 175, 219, 0.32);
  background: var(--vp-c-bg);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  cursor: pointer;
  text-align: left;
  box-shadow:
    0 12px 32px rgba(37, 175, 219, 0.1),
    0 0 0 4px rgba(37, 175, 219, 0.04);
  transition:
    transform 0.18s ease,
    border-color 0.18s ease,
    box-shadow 0.18s ease,
    background 0.18s ease;
}

.dark .install-card {
  background: rgba(255, 255, 255, 0.02);
  border-color: rgba(109, 208, 237, 0.32);
  box-shadow:
    0 12px 32px rgba(0, 0, 0, 0.4),
    0 0 0 4px rgba(109, 208, 237, 0.06);
}

.install-card:hover {
  transform: translateY(-2px);
  border-color: var(--aooth-cyan);
  box-shadow:
    0 18px 40px rgba(37, 175, 219, 0.18),
    0 0 0 4px rgba(37, 175, 219, 0.08);
}

.install-card.copied {
  border-color: #18a674;
  box-shadow:
    0 12px 32px rgba(24, 166, 116, 0.18),
    0 0 0 4px rgba(24, 166, 116, 0.08);
}

.install-prompt {
  font-size: 17px;
  font-weight: 800;
  color: var(--aooth-cyan);
  line-height: 1;
  flex-shrink: 0;
}

.install-cmd {
  flex: 1;
  font-size: 14px;
  letter-spacing: -0.1px;
  color: var(--vp-c-text-1);
  overflow-x: auto;
  white-space: nowrap;
  scrollbar-width: thin;
}

.install-cmd::-webkit-scrollbar {
  height: 4px;
}

.install-cmd::-webkit-scrollbar-thumb {
  background: var(--vp-c-divider);
  border-radius: 2px;
}

.install-cmd strong {
  color: var(--aooth-cyan);
  font-weight: 700;
}

.dark .install-cmd strong {
  color: var(--aooth-cyan-bright);
}

@media (min-width: 640px) {
  .install-cmd {
    font-size: 15px;
  }
}

.install-action {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 10px 6px 8px;
  border-radius: 999px;
  background: rgba(37, 175, 219, 0.1);
  color: var(--aooth-cyan);
  font-family: var(--vp-font-family-base);
  font-size: 11.5px;
  font-weight: 700;
  letter-spacing: 0.02em;
  white-space: nowrap;
  flex-shrink: 0;
  transition:
    background 0.2s ease,
    color 0.2s ease;
}

.dark .install-action {
  background: rgba(109, 208, 237, 0.14);
  color: var(--aooth-cyan-bright);
}

.install-card.copied .install-action {
  background: rgba(24, 166, 116, 0.12);
  color: #18a674;
}

.install-action-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 14px;
  height: 14px;
}

.install-action-icon svg {
  width: 13px;
  height: 13px;
}

@media (max-width: 520px) {
  .install-action-label {
    display: none;
  }
}

/* ─────────────────────────────────────────────
 * AI Agent Skill section
 * ───────────────────────────────────────────── */

.aooth-skill {
  padding: 96px 24px;
  position: relative;
  background:
    radial-gradient(60% 50% at 50% 0%, var(--aooth-cyan-soft), transparent 70%),
    radial-gradient(40% 40% at 50% 100%, var(--aooth-magenta-soft), transparent 70%), var(--vp-c-bg);
  border-bottom: 1px solid var(--vp-c-divider);
}

.dark .aooth-skill {
  background:
    radial-gradient(60% 50% at 50% 0%, rgba(37, 175, 219, 0.1), transparent 70%),
    radial-gradient(40% 40% at 50% 100%, rgba(219, 37, 146, 0.06), transparent 70%), #0a1722;
}

@media (min-width: 960px) {
  .aooth-skill {
    padding: 120px 64px;
  }
}

.aooth-skill-inner {
  max-width: 760px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
}

.skill-head {
  margin-bottom: 32px;
}

.skill-head .showcase-eyebrow {
  justify-content: center;
  margin-bottom: 18px;
}

.skill-title {
  margin: 0 0 16px;
  font-size: clamp(26px, 3vw, 36px);
  line-height: 1.18;
  letter-spacing: -0.015em;
  font-weight: 700;
  color: var(--vp-c-text-1);
}

.skill-desc {
  margin: 0;
  font-size: 16px;
  line-height: 1.6;
  color: var(--vp-c-text-2);
  max-width: 620px;
}

.skill-desc code {
  font-size: 13px;
  color: var(--aooth-cyan);
  background: var(--aooth-cyan-soft);
  padding: 1px 6px;
  border-radius: 5px;
  font-family: var(--vp-font-family-mono);
}

.dark .skill-desc code {
  color: var(--aooth-cyan-bright);
}

/* Install bullets */
.install-bullets {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 8px 22px;
  margin: 22px 0 6px;
  padding: 0;
  list-style: none;
}

.install-bullets li {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: var(--vp-c-text-2);
}

.install-bullets li code {
  font-size: 12.5px;
  color: var(--aooth-cyan);
  background: var(--aooth-cyan-soft);
  padding: 1px 5px;
  border-radius: 4px;
  font-family: var(--vp-font-family-mono);
}

.dark .install-bullets li code {
  color: var(--aooth-cyan-bright);
}

.bullet-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--aooth-cyan);
  flex-shrink: 0;
  opacity: 0.7;
}

.skill-link {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-top: 22px;
  font-weight: 600;
  font-size: 14px;
  color: var(--vp-c-brand-1);
  text-decoration: none;
  border-bottom: 1px solid transparent;
  transition:
    border-color 0.2s ease,
    transform 0.2s ease;
}

.skill-link:hover {
  border-bottom-color: currentColor;
}

.skill-link .arrow {
  transition: transform 0.25s ease;
}

.skill-link:hover .arrow {
  transform: translateX(3px);
}

/* ─────────────────────────────────────────────
 * Scroll-triggered reveal
 * ───────────────────────────────────────────── */

.animate-in {
  opacity: 0;
  transform: translateY(14px);
  transition:
    opacity 0.7s ease,
    transform 0.7s ease;
}

.animate-in.visible {
  opacity: 1;
  transform: translateY(0);
}

.aooth-hero .animate-in:nth-child(1) {
  transition-delay: 0s;
}
.aooth-hero .animate-in:nth-child(2) {
  transition-delay: 0.05s;
}
.aooth-hero .animate-in:nth-child(3) {
  transition-delay: 0.12s;
}
.aooth-hero .animate-in:nth-child(4) {
  transition-delay: 0.18s;
}
.aooth-hero .animate-in:nth-child(5) {
  transition-delay: 0.24s;
}
.aooth-hero .animate-in:nth-child(6) {
  transition-delay: 0.3s;
}

/* Hero's initial state should be visible without IntersectionObserver
 * because it's above the fold and may not trigger reliably. */
.aooth-hero .animate-in {
  opacity: 1;
  transform: translateY(0);
  animation: heroReveal 0.7s ease both;
}

.aooth-hero .animate-in:nth-child(2) {
  animation-delay: 0.05s;
}
.aooth-hero .animate-in:nth-child(3) {
  animation-delay: 0.12s;
}
.aooth-hero .animate-in:nth-child(4) {
  animation-delay: 0.2s;
}
.aooth-hero .animate-in:nth-child(5) {
  animation-delay: 0.28s;
}
.aooth-hero .animate-in:nth-child(6) {
  animation-delay: 0.36s;
}

@keyframes heroReveal {
  from {
    opacity: 0;
    transform: translateY(14px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@media (prefers-reduced-motion: reduce) {
  .animate-in {
    opacity: 1;
    transform: none;
    transition: none;
    animation: none !important;
  }
}
</style>
