import { Injectable } from "moost";

export const DEFAULT_MFA_CODE_TTL_MS = 5 * 60 * 1000;

/**
 * Options class for {@link LoginWorkflow}. Empty in BIG 2 — today's step
 * bodies don't read any TTL/config. The shell exists so LoginWorkflow has a
 * stable DI token to inject and consumers can wire it now. BIG 3 expands it
 * to the full ~25-field shape from `WF_LOGIN.md`.
 */
@Injectable()
export class LoginWorkflowOptions {
  constructor(opts: Partial<LoginWorkflowOptions> = {}) {
    Object.assign(this, opts);
  }
}
