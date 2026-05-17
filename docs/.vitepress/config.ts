import { defineConfig } from "vitepress";

const guideSidebar = [
  {
    text: "Getting Started",
    items: [
      { text: "Overview", link: "/guide/" },
      { text: "Quick Start", link: "/guide/quick-start" },
      { text: "Installation", link: "/guide/installation" },
      { text: "Ecosystem & Packages", link: "/guide/ecosystem" },
      { text: "Using atscript-db Models", link: "/guide/atscript-db" },
    ],
  },
];

const userSidebar = [
  {
    text: "User",
    items: [
      { text: "Overview", link: "/user/" },
      { text: "UserService", link: "/user/service" },
      { text: "Credentials Model", link: "/user/credentials" },
      { text: "Password Hashing", link: "/user/password" },
      { text: "Password Policies", link: "/user/policy" },
      { text: "MFA Primitives", link: "/user/mfa" },
      { text: "Stores", link: "/user/stores" },
      { text: "Errors", link: "/user/errors" },
    ],
  },
];

const arbacSidebar = [
  {
    text: "ARBAC",
    items: [
      { text: "Overview", link: "/arbac/" },
      { text: "Mental Model", link: "/arbac/concepts" },
      { text: "Core Engine", link: "/arbac/core" },
      { text: "Builder API", link: "/arbac/builder" },
      { text: "Privilege Factories", link: "/arbac/privileges" },
      { text: "Scope Merging", link: "/arbac/scopes" },
      { text: "Codegen", link: "/arbac/codegen" },
    ],
  },
];

const authSidebar = [
  {
    text: "Auth",
    items: [
      { text: "Overview", link: "/auth/" },
      { text: "Credentials & Sessions", link: "/auth/credentials" },
      { text: "Tokens (JWT)", link: "/auth/tokens" },
      { text: "Refresh & Rotation", link: "/auth/refresh" },
      { text: "Magic Links", link: "/auth/magic-links" },
      { text: "Password Reset", link: "/auth/password-reset" },
      { text: "Email & SMS Senders", link: "/auth/delivery" },
      { text: "Stores", link: "/auth/stores" },
      { text: "Errors", link: "/auth/errors" },
    ],
  },
];

const moostSidebar = [
  {
    text: "Moost Integration",
    items: [
      { text: "Overview", link: "/moost/" },
      { text: "Setup", link: "/moost/setup" },
      { text: "AuthGuard & useAuth", link: "/moost/auth-guard" },
      { text: "ARBAC Authorize", link: "/moost/arbac-authorize" },
      { text: "Decorators", link: "/moost/decorators" },
      { text: "REST Controllers", link: "/moost/controllers" },
      { text: "Workflows", link: "/moost/workflows" },
      { text: "DB Controllers", link: "/moost/db-controllers" },
      { text: "Atscript Models", link: "/moost/atscript" },
      { text: "Audit Log", link: "/moost/audit" },
      { text: "Config Reference", link: "/moost/config" },
    ],
  },
];

const apiSidebar = [
  {
    text: "API Reference",
    items: [
      { text: "@aooth/user", link: "/api/user" },
      { text: "@aooth/arbac-core", link: "/api/arbac-core" },
      { text: "@aooth/arbac", link: "/api/arbac" },
      { text: "@aooth/auth", link: "/api/auth" },
      { text: "@aooth/arbac-moost", link: "/api/arbac-moost" },
      { text: "@aooth/auth-moost", link: "/api/auth-moost" },
    ],
  },
];

export default defineConfig({
  title: "Aooth",
  description:
    "Authentication and authorization for the Moost and Atscript ecosystem — sessions, tokens, MFA, RBAC, ABAC, all from typed models.",
  lang: "en-US",
  lastUpdated: true,
  cleanUrls: true,

  head: [
    ["link", { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" }],
    ["link", { rel: "alternate icon", href: "/favicon.svg" }],
    ["meta", { name: "theme-color", content: "#25afdb" }],
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:title", content: "Aooth" }],
    [
      "meta",
      {
        property: "og:description",
        content:
          "Authentication and authorization for the Moost and Atscript ecosystem — sessions, tokens, MFA, RBAC, ABAC, all from typed models.",
      },
    ],
  ],

  markdown: {
    theme: { light: "github-light", dark: "github-dark" },
    lineNumbers: true,
    languages: ["typescript", "javascript", "json", "bash", "vue"] as any,
  },

  themeConfig: {
    logo: "/favicon.svg",
    siteTitle: false,

    nav: [
      { text: "Guide", link: "/guide/quick-start" },
      { text: "User", link: "/user/" },
      { text: "ARBAC", link: "/arbac/" },
      { text: "Auth", link: "/auth/" },
      { text: "Moost", link: "/moost/" },
      { text: "API", link: "/api/user" },
      {
        text: "Ecosystem",
        items: [
          { text: "Atscript", link: "https://atscript.dev" },
          { text: "Atscript DB", link: "https://db.atscript.dev" },
          { text: "Atscript UI", link: "https://ui.atscript.dev" },
          { text: "Moost", link: "https://moost.org" },
        ],
      },
    ],

    sidebar: {
      "/guide/": guideSidebar,
      "/user/": userSidebar,
      "/arbac/": arbacSidebar,
      "/auth/": authSidebar,
      "/moost/": moostSidebar,
      "/api/": apiSidebar,
    },

    socialLinks: [{ icon: "github", link: "https://github.com/moostjs/aoothjs" }],

    search: {
      provider: "local",
    },

    editLink: {
      pattern: "https://github.com/moostjs/aoothjs/edit/main/docs/:path",
      text: "Edit this page on GitHub",
    },

    footer: {
      message: "Released under the MIT License.",
      copyright: "Copyright © 2025-present Artem Maltsev",
    },
  },
});
