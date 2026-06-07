export interface TestCred {
  username: string;
  password: string;
  notes: string;
}

export interface WfDescriptor {
  id: string;
  label: string;
  description: string;
  requiresAuth: boolean;
  testCreds?: ReadonlyArray<TestCred>;
  /**
   * Trigger endpoint override. Defaults to the public `/auth/trigger`.
   * The change-password flow sets this to its GUARDED route so the SPA posts
   * to the authenticated, arbac-gated endpoint instead.
   */
  endpoint?: string;
  /**
   * Render this flow through the headless host-cancel shell instead of the
   * default `<AsWfForm>`. The manage-MFA forms hide their built-in `cancel`
   * action (it stays in the whitelist); a host that wants a Cancel affordance
   * supplies its own and dispatches the `cancel` action so the flow aborts and
   * its durable wf-state row is cleaned up. The demo's `<WfHostCancelForm>` is
   * the reference implementation of that consumer-side pattern.
   */
  hostCancel?: boolean;
}

// All seeded users carry the same password — keeping it as a constant here
// (and reading it back into every row) so the matrix shows it explicitly per
// user without needing the operator to remember it cross-row.
const PWD = "Password1!";

const LOGIN_USERS: ReadonlyArray<TestCred> = [
  { username: "t1_alice", password: PWD, notes: "Happy path — no MFA." },
  {
    username: "t1_grace",
    password: PWD,
    notes:
      "TOTP MFA. Secret is logged to the dev console at seed time — copy it into an authenticator app.",
  },
  {
    username: "t1_henry",
    password: PWD,
    notes:
      "Email-OTP MFA. Pincode arrives via the console email sender — watch the server log for `[email] login.pincode → henry@acme.test code=…`.",
  },
  {
    username: "t1_ivy",
    password: PWD,
    notes:
      "SMS-OTP MFA. Pincode goes to the demo SMS sender — watch the server log for `[demo SMS] login.pincode +15555550101 …`.",
  },
  {
    username: "t1_jack",
    password: PWD,
    notes:
      "`password.isInitial = true` — login pauses on the set-password step before issuing tokens.",
  },
  {
    username: "t1_stale",
    password: PWD,
    notes:
      "`password.lastChanged = 1` (epoch+1ms) — exceeds `password.maxAgeMs` (365d). Use with the `password-expired` variant to exercise the rotation-driven forced password change.",
  },
  {
    username: "t1_locked",
    password: PWD,
    notes: "`account.locked = true` — login is expected to surface a 423 friendly error.",
  },
  {
    username: "t1_multi_mfa",
    password: PWD,
    notes:
      "Three confirmed MFA methods (email + SMS + TOTP, default = TOTP) — `Select2faForm` fires.",
  },
  {
    username: "t1_active_sessions",
    password: PWD,
    notes:
      "Two pre-minted access tokens — `concurrencyLimit.max = 1` variant trips the kickPrompt branch.",
  },
  {
    username: "t1_terms_old",
    password: PWD,
    notes:
      "Variant config flags this user with `termsAcceptedVersion = 'v0'` so the terms-accept step fires.",
  },
  {
    username: "_admin_inviter",
    password: PWD,
    notes:
      "Dedicated `admin`-role user for invite-side stories — sign in here, then visit `/wf?id=auth/invite/start` to send invitations.",
  },
];

const ADMIN_USERS: ReadonlyArray<TestCred> = [
  { username: "t1_dave", password: PWD, notes: "Tenant-A admin (`roles: ['admin']`)." },
  { username: "t2_olivia", password: PWD, notes: "Tenant-B admin." },
  {
    username: "_super",
    password: PWD,
    notes: "Cross-tenant superadmin (`roles: ['superadmin']`).",
  },
];

const INVITE_ADMIN_USERS: ReadonlyArray<TestCred> = [
  ...ADMIN_USERS,
  {
    username: "_admin_inviter",
    password: PWD,
    notes: "Dedicated `admin`-role user for invite-side stories (grants `auth.invite/start`).",
  },
];

// Single-method users have exactly one of three transports enrolled, so the
// add-MFA picker offers the other two; `t1_multi_mfa` has all three (nothing to
// add). `t1_alice` has none — the picker offers all three.
const ADD_MFA_USERS: ReadonlyArray<TestCred> = [
  { username: "t1_grace", password: PWD, notes: "Has TOTP — can add Email-OTP or SMS-OTP." },
  { username: "t1_henry", password: PWD, notes: "Has Email-OTP — can add SMS-OTP or TOTP." },
  { username: "t1_ivy", password: PWD, notes: "Has SMS-OTP — can add Email-OTP or TOTP." },
  {
    username: "t1_multi_mfa",
    password: PWD,
    notes: "Email + SMS + TOTP all enrolled — the flow reports nothing left to add.",
  },
  { username: "t1_alice", password: PWD, notes: "No MFA — the picker offers all three." },
];

export const WORKFLOWS: ReadonlyArray<WfDescriptor> = [
  {
    id: "auth/login/flow",
    label: "Login",
    description:
      "Username/password with optional MFA (TOTP / email-OTP / SMS-OTP / backup codes) and a forced-password-change branch.",
    requiresAuth: false,
    testCreds: LOGIN_USERS,
  },
  {
    id: "auth/recovery/flow",
    label: "Password recovery",
    description:
      "Forgot-password — OTP-via-email. Any seeded email works; default finish redirects to login, recovery-auto-login variant issues tokens.",
    requiresAuth: false,
    testCreds: LOGIN_USERS,
  },
  {
    id: "auth/invite/start",
    label: "Invite user (admin)",
    description: "Admin creates a pending invitation; resume via emailed magic link.",
    requiresAuth: true,
    testCreds: INVITE_ADMIN_USERS,
  },
  {
    id: "project.handover",
    label: "Project handover",
    description: "Demo-specific app workflow (transfer project ownership).",
    requiresAuth: true,
    testCreds: ADMIN_USERS,
  },
  {
    id: "auth/change-password/flow",
    label: "Change password",
    description:
      "Authenticated user changes their own password — verifies the current password, then revokes other sessions and rotates the acting token.",
    requiresAuth: true,
    testCreds: LOGIN_USERS,
    // GUARDED trigger — authenticated + the `auth:change-password` privilege
    // (NOT the public `/auth/trigger`).
    endpoint: "/auth/change-password",
  },
  {
    id: "auth/add-mfa/flow",
    label: "Manage MFA",
    description:
      "Authenticated user manages their two-factor methods — add / change / remove. If they already have a factor it first STEPS UP (verifies an existing one), then shows a menu; a zero-MFA user goes straight to the enrol picker. TOTP shows the QR on its own step before code entry. Handle-bound factors (an MFA email/phone that is also a login handle) are locked from change/remove. Sign in as a single-method user (t1_grace TOTP, t1_henry email, t1_ivy SMS) or t1_multi_mfa (all three).",
    requiresAuth: true,
    testCreds: ADD_MFA_USERS,
    // GUARDED trigger — authenticated + the `auth:add-mfa` privilege (NOT the
    // public `/auth/trigger`).
    endpoint: "/auth/add-mfa",
    // The manage-MFA forms hide their built-in `cancel`, so render through the
    // host-cancel shell which supplies its own Cancel button.
    hostCancel: true,
  },
];
