import { generateSecureRandom } from "../utils";

/**
 * Custom alphabet for backup codes — uppercase letters and digits with the
 * easily-confused characters (I, O, L, 0, 1) removed (31 chars).
 */
const BACKUP_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

const RAW_LENGTH = 10;
const GROUP_SIZE = 4;

/**
 * Generate `count` cryptographically-random backup codes (default 10).
 *
 * Format: 10 characters from the 31-char safe alphabet (uppercase letters +
 * digits, omitting I/O/L/0/1), grouped as `XXXX-XXXX-XX`.
 *
 * Returns plaintext codes for the caller to deliver to the user — these
 * should be hashed via {@link hashMfaCode} before persistence and never
 * shown to the user again.
 */
export function generateBackupCodePlaintext(count = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    codes.push(formatCode(generateSecureRandom(RAW_LENGTH, BACKUP_CODE_ALPHABET)));
  }
  return codes;
}

function formatCode(raw: string): string {
  const parts: string[] = [];
  for (let i = 0; i < raw.length; i += GROUP_SIZE) {
    parts.push(raw.slice(i, i + GROUP_SIZE));
  }
  return parts.join("-");
}
