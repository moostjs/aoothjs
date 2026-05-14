import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test"

import { buildTestApp, type TestApp } from "./harness"

describe("test harness smoke", () => {
  let app: TestApp

  beforeAll(async () => {
    app = await buildTestApp()
  })
  afterAll(async () => {
    await app.close()
  })

  it("boots an app and serves /health", async () => {
    const res = await app.fetch("/health")
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true })
  })

  it("exposes seeded fixtures", () => {
    expect(app.fixtures.users.t1_alice.username).toBe("t1_alice")
    expect(app.fixtures.users.t1_alice.roles).toEqual(["member", "viewer"])
    expect(app.fixtures.users.t1_grace.totpSecret).toBeTruthy()
  })

  it("logs in a seeded user", async () => {
    const tokens = await app.loginAs(app.fixtures.users.t1_alice)
    expect(tokens.accessToken).toBeTruthy()
    expect(tokens.refreshToken).toBeTruthy()
    expect(tokens.userId).toBe("t1_alice")
  })

  it("authedFetch reaches a protected route", async () => {
    const tokens = await app.loginAs(app.fixtures.users.t1_alice)
    const res = await app.authedFetch(tokens.accessToken)("/auth/status")
    expect(res.status).toBe(200)
    const ctx = (await res.json()) as { userId: string }
    expect(ctx.userId).toBe("t1_alice")
  })

  it("captures workflow emails", async () => {
    const bob = app.fixtures.users.t1_bob
    const r1 = await app.triggerWf("public", { wfid: "auth.recovery" })
    const r1body = (await r1.json()) as { wfs?: string }
    expect(r1body.wfs).toBeTruthy()
    await app.triggerWf("public", {
      wfid: "auth.recovery",
      wfs: r1body.wfs,
      input: { email: bob.email },
    })
    const ev = await app.emailSender.next(
      (e) => e.kind === "recovery.magicLink" && e.recipient === bob.email,
      2000,
    )
    expect(ev.url).toContain("?wfs=")
  })
})
