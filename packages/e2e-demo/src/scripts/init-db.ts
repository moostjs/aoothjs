import { buildApp } from "../app"
import { seedAll } from "../seed"

async function main(): Promise<void> {
  const handle = await buildApp({
    dbPath: process.env.DB_PATH ?? "./e2e-demo.sqlite",
    port: 0,
  })
  // biome-ignore lint/suspicious/noConsole: db init script
  console.log("Schema synced.")
  const fixtures = await seedAll(handle)
  // biome-ignore lint/suspicious/noConsole: db init script
  console.log(`Seeded ${Object.keys(fixtures.users).length} users`)
  // biome-ignore lint/suspicious/noConsole: db init script
  console.log(`Tenants: A=${fixtures.tenants["tenant-a"]}, B=${fixtures.tenants["tenant-b"]}`)
  await handle.close()
  // biome-ignore lint/suspicious/noConsole: db init script
  console.log("Done.")
}

main().catch((err) => {
  // biome-ignore lint/suspicious/noConsole: db init script
  console.error(err)
  process.exit(1)
})
