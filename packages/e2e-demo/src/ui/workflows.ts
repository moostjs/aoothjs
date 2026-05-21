export interface WfDescriptor {
  id: string;
  label: string;
  description: string;
  /** Does the workflow expect an authenticated session before it'll start? */
  requiresAuth: boolean;
}

export const WORKFLOWS: ReadonlyArray<WfDescriptor> = [
  {
    id: "auth.login",
    label: "Login",
    description:
      "Username/password (+ optional MFA). Try: t1_alice (no MFA), t1_grace (TOTP), t1_henry (email OTP), t1_ivy (SMS OTP), t1_jack (forced password change). All passwords: Password1!",
    requiresAuth: false,
  },
  {
    id: "auth.recovery",
    label: "Password recovery",
    description:
      "Forgot-password — magic link or OTP. Email-recoverable: any seeded user. SMS-recoverable: t1_ivy.",
    requiresAuth: false,
  },
  {
    id: "auth.invite",
    label: "Invite user (admin)",
    description: "Admin creates a pending invitation; resume via emailed magic link.",
    requiresAuth: true,
  },
  {
    id: "auth.reInvite",
    label: "Re-invite user (admin)",
    description: "Resend invitation to a pending user.",
    requiresAuth: true,
  },
  {
    id: "auth.cancelInvite",
    label: "Cancel pending invite (admin)",
    description: "Delete a pending invitation before acceptance.",
    requiresAuth: true,
  },
  {
    id: "project.handover",
    label: "Project handover",
    description: "Demo-specific app workflow (transfer project ownership).",
    requiresAuth: true,
  },
];
