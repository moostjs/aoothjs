export { type ArbacUserTable, AtscriptArbacUserProvider } from "./auto-provider";
export {
  type ArbacAttenuationSpec,
  extractAttenuation,
  getArbacAttenuationSpec,
  validateAttenuationTargets,
} from "./attenuation-extract";
export {
  type AoothCredentialMetadataSpec,
  getAoothCredentialMetadataSpec,
} from "./credential-metadata-spec";
export { type AoothUserHandleSpec, getAoothUserHandleSpec } from "./handle-spec";

export { AoothArbacUserCredentials } from "./models/user.as";
