<script setup>
// Decorative SVG: circuit-style paths flowing rightward, animated stroke
// dash-offset. Subtle dot grid + cyan glow + a single magenta accent ring
// (mirroring the wordmark's magenta loop).
</script>

<template>
  <div class="auth-flow-bg" aria-hidden="true">
    <svg
      class="auth-flow-svg"
      viewBox="0 0 1200 600"
      preserveAspectRatio="xMaxYMid slice"
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <radialGradient id="cyanGlow" cx="80%" cy="40%" r="40%">
          <stop offset="0%" stop-color="#25AFDB" stop-opacity="0.16" />
          <stop offset="60%" stop-color="#25AFDB" stop-opacity="0.03" />
          <stop offset="100%" stop-color="#25AFDB" stop-opacity="0" />
        </radialGradient>
        <radialGradient id="magentaGlow" cx="92%" cy="18%" r="14%">
          <stop offset="0%" stop-color="#DB2592" stop-opacity="0.10" />
          <stop offset="100%" stop-color="#DB2592" stop-opacity="0" />
        </radialGradient>
        <pattern id="dotGrid" x="0" y="0" width="22" height="22" patternUnits="userSpaceOnUse">
          <circle cx="1" cy="1" r="1" fill="currentColor" opacity="0.05" />
        </pattern>
        <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="2" />
        </filter>
      </defs>

      <!-- Soft glows -->
      <rect width="1200" height="600" fill="url(#cyanGlow)" />
      <rect width="1200" height="600" fill="url(#magentaGlow)" />

      <!-- Dot grid base -->
      <rect width="1200" height="600" fill="url(#dotGrid)" class="dot-grid" />

      <!-- Circuit paths flowing rightward -->
      <g class="circuit" fill="none" stroke="#25AFDB" stroke-width="1" opacity="0.22">
        <path class="path path-1" d="M 0 120 L 380 120 L 420 160 L 720 160 L 760 120 L 1200 120" />
        <path class="path path-2" d="M 0 240 L 520 240 L 560 280 L 1200 280" />
        <path class="path path-3" d="M 0 360 L 320 360 L 360 400 L 880 400 L 920 360 L 1200 360" />
        <path class="path path-4" d="M 0 480 L 660 480 L 700 440 L 1200 440" />
      </g>

      <!-- Node dots along paths -->
      <g class="nodes" fill="#25AFDB" opacity="0.40">
        <circle cx="420" cy="160" r="2.5" />
        <circle cx="760" cy="120" r="2.5" />
        <circle cx="560" cy="280" r="2.5" />
        <circle cx="360" cy="400" r="2.5" />
        <circle cx="920" cy="360" r="2.5" />
        <circle cx="700" cy="440" r="2.5" />
      </g>

      <!-- Magenta accent ring (mirrors the wordmark loop) -->
      <g class="accent-ring" transform="translate(1050 90)">
        <circle r="34" fill="none" stroke="#DB2592" stroke-width="2" opacity="0.28" />
        <circle
          r="34"
          fill="none"
          stroke="#DB2592"
          stroke-width="3"
          opacity="0.10"
          filter="url(#glow)"
        />
      </g>

      <!-- A few stylized padlock pins floating -->
      <g class="pins" fill="none" stroke="#25AFDB" stroke-width="1.2" opacity="0.22">
        <g transform="translate(880 60)">
          <rect x="-9" y="-2" width="18" height="14" rx="2" />
          <path d="M -5 -2 V -7 a 5 5 0 0 1 10 0 V -2" />
        </g>
        <g transform="translate(620 520)">
          <rect x="-9" y="-2" width="18" height="14" rx="2" />
          <path d="M -5 -2 V -7 a 5 5 0 0 1 10 0 V -2" />
        </g>
      </g>
    </svg>
  </div>
</template>

<style scoped>
.auth-flow-bg {
  position: absolute;
  inset: 0;
  pointer-events: none;
  z-index: 1;
  color: #25afdb;
  overflow: hidden;
}

.auth-flow-svg {
  width: 100%;
  height: 100%;
  display: block;
}

.path {
  stroke-dasharray: 8 6;
  stroke-dashoffset: 0;
  animation: dashFlow 9s linear infinite;
}
.path-2 {
  animation-duration: 12s;
  animation-direction: reverse;
}
.path-3 {
  animation-duration: 14s;
}
.path-4 {
  animation-duration: 11s;
  animation-direction: reverse;
}

.nodes circle {
  animation: nodePulse 3.2s ease-in-out infinite;
  transform-origin: center;
  transform-box: fill-box;
}
.nodes circle:nth-child(2) {
  animation-delay: 0.4s;
}
.nodes circle:nth-child(3) {
  animation-delay: 0.8s;
}
.nodes circle:nth-child(4) {
  animation-delay: 1.2s;
}
.nodes circle:nth-child(5) {
  animation-delay: 1.6s;
}
.nodes circle:nth-child(6) {
  animation-delay: 2s;
}

.accent-ring {
  animation: ringFloat 6s ease-in-out infinite;
  transform-origin: center;
  transform-box: fill-box;
}

.pins g {
  animation: pinFloat 7s ease-in-out infinite;
}
.pins g:nth-child(2) {
  animation-delay: 1.4s;
  animation-duration: 9s;
}

@keyframes dashFlow {
  to {
    stroke-dashoffset: -280;
  }
}

@keyframes nodePulse {
  0%,
  100% {
    r: 3.5;
    opacity: 0.9;
  }
  50% {
    r: 5;
    opacity: 0.55;
  }
}

@keyframes ringFloat {
  0%,
  100% {
    transform: translate(1050px, 90px) scale(1);
  }
  50% {
    transform: translate(1050px, 100px) scale(1.06);
  }
}

@keyframes pinFloat {
  0%,
  100% {
    transform: translate(880px, 60px);
  }
  50% {
    transform: translate(880px, 48px);
  }
}

.dark .dot-grid {
  opacity: 1.4;
}

@media (prefers-reduced-motion: reduce) {
  .path,
  .nodes circle,
  .accent-ring,
  .pins g {
    animation: none;
  }
}
</style>
