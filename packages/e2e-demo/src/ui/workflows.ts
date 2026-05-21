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
    username: "t1_kate",
    password: PWD,
    notes:
      "TOTP MFA + 10 backup codes. Plaintext codes are logged to the dev console at seed time; pick action `useBackupCode` on the MFA step.",
  },
  {
    username: "t1_jack",
    password: PWD,
    notes:
      "`password.isInitial = true` — login pauses on the set-password step before issuing tokens.",
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
    username: "t1_profile_incomplete",
    password: PWD,
    notes:
      "Variant config flags `profileMissingFields = ['firstName','lastName']` so the profile-complete step fires.",
  },
  {
    username: "t1_two_tenants",
    password: PWD,
    notes:
      "Shares an email with `t2_two_tenants` — the tenant-select variant should offer both as picker options.",
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

// Adds the pending / redeemed target users as non-login hints for the operator.
const REINVITE_ADMIN_USERS: ReadonlyArray<TestCred> = [
  ...INVITE_ADMIN_USERS,
  {
    username: "t1_pending",
    password: "n/a — target user",
    notes: "Target email for reInvite happy path (record is `pendingInvitation = true`).",
  },
  {
    username: "t1_redeemed",
    password: "n/a — target user",
    notes:
      "Target email for the 409 path — user already accepted, reInvite/cancelInvite should refuse.",
  },
];

export const WORKFLOWS: ReadonlyArray<WfDescriptor> = [
  {
    id: "auth.login",
    label: "Login",
    description:
      "Username/password with optional MFA (TOTP / email-OTP / SMS-OTP / backup codes) and a forced-password-change branch.",
    requiresAuth: false,
    testCreds: LOGIN_USERS,
  },
  {
    id: "auth.recovery",
    label: "Password recovery",
    description:
      "Forgot-password — magic link or OTP. Any seeded email works; SMS-recoverable via t1_ivy's phone.",
    requiresAuth: false,
    testCreds: LOGIN_USERS,
  },
  {
    id: "auth.invite",
    label: "Invite user (admin)",
    description: "Admin creates a pending invitation; resume via emailed magic link.",
    requiresAuth: true,
    testCreds: INVITE_ADMIN_USERS,
  },
  {
    id: "auth.reInvite",
    label: "Re-invite user (admin)",
    description: "Resend invitation to a pending user.",
    requiresAuth: true,
    testCreds: REINVITE_ADMIN_USERS,
  },
  {
    id: "auth.cancelInvite",
    label: "Cancel pending invite (admin)",
    description: "Delete a pending invitation before acceptance.",
    requiresAuth: true,
    testCreds: REINVITE_ADMIN_USERS,
  },
  {
    id: "project.handover",
    label: "Project handover",
    description: "Demo-specific app workflow (transfer project ownership).",
    requiresAuth: true,
    testCreds: ADMIN_USERS,
  },
];
