import { generateTotpCode } from "@aoothjs/user"
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test"

import {
  buildTestApp,
  expectOk,
  installDyeStubs,
  readWfPause,
  type TestApp,
  wfErrors,
} from "./harness"

installDyeStubs()

describe("WF-LOGIN — auth.login workflow", () => {
  let app: TestApp

  beforeAll(async () => {
    app = await buildTestApp()
  })
  afterAll(async () => {
    await app.close()
  })
  beforeEach(() => {
    app.emailSender.reset()
  })

  it("WF-LOGIN-01 — credentials step (no MFA) finishes immediately with tokens", async () => {
    const start = await app.triggerWf("public", { wfid: "auth.login" })
    expectOk(start)
    const startBody = await readWfPause(start)
    expect(startBody.wfs).toBeTruthy()
    expect(startBody.inputRequired).toBeTruthy()

    const alice = app.fixtures.users.t1_alice
    const submit = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: startBody.wfs,
      input: { username: alice.username, password: alice.password },
    })
    expectOk(submit)
    const finished = (await submit.json()) as {
      userId?: string
      accessToken?: string
      refreshToken?: string
      inputRequired?: unknown
    }
    expect(finished.inputRequired).toBeUndefined()
    expect(finished.userId).toBe(alice.username)
    expect(typeof finished.accessToken).toBe("string")
    expect(typeof finished.refreshToken).toBe("string")
  })

  it("WF-LOGIN-02 — MFA required branch: credentials → MFA form → valid TOTP → tokens", async () => {
    const grace = app.fixtures.users.t1_grace
    expect(grace.totpSecret).toBeTruthy()

    const start = await app.triggerWf("public", { wfid: "auth.login" })
    const startBody = await readWfPause(start)

    const credResp = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: startBody.wfs,
      input: { username: grace.username, password: grace.password },
    })
    expectOk(credResp)
    const credBody = await readWfPause(credResp)
    expect(credBody.inputRequired).toBeTruthy()

    const wrong = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: credBody.wfs,
      input: { code: "000000" },
    })
    const wrongBody = await readWfPause(wrong)
    expect(wfErrors(wrongBody)).toMatchObject({ code: "Invalid code" })

    const code = generateTotpCode(grace.totpSecret as string)
    const final = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: wrongBody.wfs,
      input: { code },
    })
    expectOk(final)
    const issued = (await final.json()) as {
      userId?: string
      accessToken?: string
    }
    expect(issued.userId).toBe(grace.username)
    expect(typeof issued.accessToken).toBe("string")
  })

  it("WF-LOGIN-03 — MFA bypass attempt with empty/skip input still requires a code", async () => {
    const grace = app.fixtures.users.t1_grace
    const start = await app.triggerWf("public", { wfid: "auth.login" })
    const startBody = await readWfPause(start)

    const credResp = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: startBody.wfs,
      input: { username: grace.username, password: grace.password },
    })
    const credBody = await readWfPause(credResp)

    const skipAttempt = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: credBody.wfs,
      input: { __skip: true },
    })
    expect([200, 201, 400]).toContain(skipAttempt.status)
    const skipBody = await readWfPause(skipAttempt)
    expect(skipBody.inputRequired ?? skipBody.wfs).toBeTruthy()
    if (skipBody.inputRequired) {
      expect(wfErrors(skipBody)).toBeTruthy()
    }

    const emptyAttempt = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: skipBody.wfs ?? credBody.wfs,
      input: {},
    })
    const emptyBody = await readWfPause(emptyAttempt)
    expect(emptyBody.inputRequired).toBeTruthy()
    expect(wfErrors(emptyBody)).toBeTruthy()
  })
})
