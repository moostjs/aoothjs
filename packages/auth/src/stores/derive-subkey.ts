import { hkdfSync } from "node:crypto";

// Fixed app-wide salt for HKDF domain separation of credential-store subkeys.
const SUBKEY_SALT = Buffer.from("aooth/credential-store/subkey-v1");

/** HKDF-SHA256 a stable 32-byte subkey from symmetric key material + a label. */
export function hkdfSubkey(ikm: Uint8Array, label: string): Buffer {
  return Buffer.from(hkdfSync("sha256", ikm, SUBKEY_SALT, Buffer.from(label, "utf8"), 32));
}
