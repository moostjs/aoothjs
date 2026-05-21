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
    description: "Username/password login with optional MFA branches.",
    requiresAuth: false,
  },
  {
    id: "auth.recovery",
    label: "Password recovery",
    description: "Forgot-password — magic link or OTP.",
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
