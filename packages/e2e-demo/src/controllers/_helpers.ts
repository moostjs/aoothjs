import { HttpError } from "@moostjs/event-http";

export function assertWritten(
  result: { matchedCount?: number; deletedCount?: number },
  message = "Not found or no permission",
): void {
  if ((result.matchedCount ?? result.deletedCount ?? 0) === 0) {
    throw new HttpError(404, message);
  }
}
