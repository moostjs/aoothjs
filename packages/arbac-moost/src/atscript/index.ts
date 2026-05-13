export type { ArbacUserIdResolver } from "./auto-provider";
export { AutoArbacUserProvider } from "./auto-provider";
export { extractArbacAttrs, extractArbacRoles, extractArbacUserId } from "./extract";
export { getArbacProjection } from "./projection";
export type { ArbacUserReader, ArbacUserTable, SetupArbacFromAtscriptOptions } from "./setup";
export { setupArbacFromAtscript } from "./setup";
export type { UserRecordFetcher } from "./wooks";
export { setUserRecordFetcher, useUserRecord } from "./wooks";

export { AoothArbacUserCredentials } from "./models/user.as";
