import { createAooth } from "../aooth"
import { createAppDb, syncAppSchema } from "../db"
import { CaptureEmailSender } from "../email/capture-email-sender"
import { ConsoleEmailSender } from "../email/console-email-sender"
import { ENV } from "../env"
import { createWfStore } from "../wf-store"

async function main() {
  // biome-ignore lint/suspicious/noConsole: smoke probe
  console.log(`[probe] ENV.PORT=${ENV.PORT} ENV.DB_PATH=${ENV.DB_PATH}`)

  const appDb = createAppDb(":memory:")
  await syncAppSchema(appDb)
  // biome-ignore lint/suspicious/noConsole: smoke probe
  console.log("[probe] schema synced")

  const wfStore = createWfStore(appDb)
  // biome-ignore lint/suspicious/noConsole: smoke probe
  console.log(`[probe] wf-store ready: ${wfStore.constructor.name}`)

  const aooth = createAooth({ tables: appDb.tables, env: ENV })
  // biome-ignore lint/suspicious/noConsole: smoke probe
  console.log(
    `[probe] aooth ready: authCredential=${aooth.authCredential.constructor.name}, userService=${aooth.userService.constructor.name}, magicLinkSample=${aooth.buildMagicLinkUrl("recovery", "abc")}`,
  )

  const consoleSender = new ConsoleEmailSender()
  const captureSender = new CaptureEmailSender()
  await consoleSender.send({
    kind: "recovery.magicLink",
    recipient: "probe@example.test",
    url: "http://example.test/recover?wfs=xyz",
    expiresAt: Date.now() + 60_000,
  })
  await captureSender.send({
    kind: "invite.magicLink",
    recipient: "probe@example.test",
    url: "http://example.test/accept-invite?wfs=xyz",
    expiresAt: Date.now() + 60_000,
  })
  // biome-ignore lint/suspicious/noConsole: smoke probe
  console.log(`[probe] capture queue size=${captureSender.events.length}`)

  // Round-trip insert + read to confirm the schema actually materialised.
  await appDb.tables.tenants.insertOne({ name: "probe-tenant", plan: "free" })
  const count = await appDb.tables.tenants.count({ filter: {} })
  // biome-ignore lint/suspicious/noConsole: smoke probe
  console.log(`[probe] tenants.count=${count}`)
  if (count !== 1) throw new Error(`expected 1 tenant after insert, got ${count}`)

  appDb.close()
  // biome-ignore lint/suspicious/noConsole: smoke probe
  console.log("[probe] OK")
}

main().catch((err) => {
  // biome-ignore lint/suspicious/noConsole: smoke probe
  console.error("[probe] FAILED", err)
  process.exit(1)
})
