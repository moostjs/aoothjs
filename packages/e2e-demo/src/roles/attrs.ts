export interface UserAttrs {
  tenantId: string;
  departmentId?: string;
  /**
   * Login handle — ownership columns store usernames, while scope fns'
   * `userId` is the surrogate `id` (supplied by `DemoArbacUserProvider.getAttrs`).
   */
  username?: string;
}

export type { ArbacDbScope } from "@aooth/arbac-moost";
