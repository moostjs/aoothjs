import { AuthCredential, CredentialStoreMemory } from "@aooth/auth";
import {
  ppHasMinLength,
  UserAuthError,
  type UserAuthErrorType,
  UserService,
  UserStoreMemory,
} from "@aooth/user";
import { Body, HttpError, Post } from "@moostjs/event-http";
import { Controller, Intercept } from "moost";
import { describe, expect, it, vi } from "vite-plus/test";

import { Public } from "../auth.decorator";
import { ConsentStore } from "../consent.store";
import { userAuthErrorInterceptor, userAuthErrorToHttp } from "../user-errors";
import { AuthWorkflow } from "../workflow/auth-workflow";
import { prepareControllerApp } from "./controller-utils";
import { prepareFlowApp } from "./flow-utils";

describe("userAuthErrorToHttp", () => {
  it.each<[UserAuthErrorType, number, string | undefined]>([
    ["NOT_FOUND", 404, undefined],
    ["ALREADY_EXISTS", 409, undefined],
    ["CAS_EXHAUSTED", 409, undefined],
    ["INVALID_CREDENTIALS", 400, "currentPassword"],
    ["POLICY_VIOLATION", 422, "newPassword"],
    ["PASSWORD_IN_HISTORY", 400, "newPassword"],
    ["PASSWORDS_MISMATCH", 400, "confirmPassword"],
    ["MFA_INVALID", 400, undefined],
    ["MFA_NOT_CONFIGURED", 400, undefined],
    ["MFA_REQUIRED", 403, undefined],
    ["INACTIVE", 403, undefined],
    ["LOCKED", 403, undefined],
  ])("%s → %i (field %s)", (type, status, field) => {
    const err = userAuthErrorToHttp(new UserAuthError(type));
    expect(err).toBeInstanceOf(HttpError);
    expect(err.body.statusCode).toBe(status);
    expect(err.body.code).toBe(type);
    expect(err.body.message).toBe(new UserAuthError(type).message);
    expect(err.body.field).toBe(field);
  });

  it("POLICY_VIOLATION carries the per-policy results as params; other details stay private", () => {
    const policies = [{ description: "Minimum length 12", passed: false }];
    const violation = userAuthErrorToHttp(
      new UserAuthError("POLICY_VIOLATION", "Too short", { policies }),
    );
    expect(violation.body.params).toEqual({ policies });
    expect(violation.body.message).toBe("Too short");
    const locked = userAuthErrorToHttp(
      new UserAuthError("LOCKED", undefined, { reason: "internal note", lockEnds: 1 }),
    );
    expect(locked.body.params).toBeUndefined();
  });
});

@Controller("admin")
@Intercept(userAuthErrorInterceptor)
class AdminController {
  constructor(private readonly users: UserService) {}

  @Post("set-password")
  @Public()
  async setPassword(@Body() body: { id: string; password: string }): Promise<{ ok: true }> {
    await this.users.setPassword(body.id, body.password);
    return { ok: true };
  }

  @Post("boom")
  @Public()
  boom(): never {
    throw new Error("not a user error");
  }
}

async function setup() {
  return prepareControllerApp({
    endpoints: false,
    extraControllers: [AdminController],
    userConfig: { password: { policies: [ppHasMinLength(12)] } },
  });
}

describe("userAuthErrorInterceptor", () => {
  it("answers a UserService error with its 4xx (code, field, params)", async () => {
    const app = await setup();
    const user = await app.users.createUser("alice", "a-long-password-1");
    const short = await app.request("/admin/set-password", {
      method: "POST",
      json: { id: user.id, password: "short" },
    });
    expect(short.status).toBe(422);
    expect(short.body).toMatchObject({
      code: "POLICY_VIOLATION",
      field: "newPassword",
      params: { policies: [{ passed: false }] },
    });
    const reused = await app.request("/admin/set-password", {
      method: "POST",
      json: { id: user.id, password: "a-long-password-1" },
    });
    expect(reused.status).toBe(400);
    expect(reused.body).toMatchObject({ code: "PASSWORD_IN_HISTORY", field: "newPassword" });
    const missing = await app.request("/admin/set-password", {
      method: "POST",
      json: { id: "nope", password: "another-long-password" },
    });
    expect(missing.status).toBe(404);
    expect(missing.body).toMatchObject({ code: "NOT_FOUND" });
  });

  it("leaves other errors alone", async () => {
    const app = await setup();
    const res = await app.request("/admin/boom", { method: "POST" });
    expect(res.status).toBe(500);
  });
});

describe("bundled workflow store-error translation", () => {
  it("answers CAS_EXHAUSTED with the coded 409", async () => {
    class Exposed extends AuthWorkflow {
      run<T>(op: () => Promise<T>): Promise<T> {
        return this.withStoreErrorTranslation(op);
      }
    }
    const wf = new Exposed(
      {},
      new UserService(new UserStoreMemory()),
      new AuthCredential({ store: new CredentialStoreMemory() }),
      new ConsentStore(),
    );
    const thrown = await wf
      .run(() => Promise.reject(new UserAuthError("CAS_EXHAUSTED")))
      .catch((e: unknown) => e);
    expect(thrown).toBeInstanceOf(HttpError);
    expect((thrown as HttpError).body).toMatchObject({ statusCode: 409, code: "CAS_EXHAUSTED" });
  });
});

describe("bundled TOTP step", () => {
  it("answers a CAS_EXHAUSTED from verifyMfa with the coded 409", async () => {
    const app = await prepareFlowApp();
    const userId = await app.seedUser("tina", "Password123!");
    await app.users.update(userId, {
      mfa: {
        methods: [{ name: "totp", value: "JBSWY3DPEHPK3PXP", confirmed: true }],
        defaultMethod: "totp",
      },
    } as never);
    const atTotp = await app.login("tina", "Password123!");
    expect(atTotp.status, JSON.stringify(atTotp.body).slice(0, 300)).toBe(201);
    const spy = vi
      .spyOn(app.users, "verifyMfa")
      .mockRejectedValueOnce(new UserAuthError("CAS_EXHAUSTED"));
    const res = await app.submit(atTotp.body.wfs, {
      formData: { code: "123456", rememberDevice: false },
    });
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
    expect(res.status).toBe(409);
    expect(res.body).toMatchObject({ code: "CAS_EXHAUSTED" });
  });
});
