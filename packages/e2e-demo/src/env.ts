export const ENV = {
  PORT: Number(process.env.PORT ?? 3001),
  DB_PATH: process.env.DB_PATH ?? ":memory:",
  FRONTEND_URL: process.env.FRONTEND_URL ?? "http://localhost:5173",
  JWT_SECRET: process.env.JWT_SECRET ?? "e2e-demo-secret-do-not-use-in-prod",
  ACCESS_TTL_MS: Number(process.env.ACCESS_TTL_MS ?? 60 * 60 * 1000),
  REFRESH_TTL_MS: Number(process.env.REFRESH_TTL_MS ?? 30 * 24 * 60 * 60 * 1000),
  LOCKOUT_THRESHOLD: Number(process.env.LOCKOUT_THRESHOLD ?? 3),
  LOCKOUT_DURATION_MS: Number(process.env.LOCKOUT_DURATION_MS ?? 5_000),
  RECOVERY_TTL_MS: Number(process.env.RECOVERY_TTL_MS ?? 60 * 60 * 1000),
  INVITE_TTL_MS: Number(process.env.INVITE_TTL_MS ?? 7 * 24 * 60 * 60 * 1000),
} as const

export type AppEnv = typeof ENV
