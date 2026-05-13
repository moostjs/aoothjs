import { describe, expect, it } from "vite-plus/test";

import type { AuthEmailEvent, AuthEmailKind, EmailSender } from "../email";

describe("EmailSender contract", () => {
  it("accepts each known AuthEmailKind value via a typed fixture", async () => {
    const sent: AuthEmailEvent[] = [];
    const sender: EmailSender = {
      send(event) {
        sent.push(event);
        return Promise.resolve();
      },
    };

    const recovery: AuthEmailEvent = {
      kind: "recovery.magicLink",
      recipient: "alice@example.com",
      url: "https://app.example.com/reset?wfs=tok1",
      expiresAt: 1_700_000_000_000,
      username: "alice",
    };
    const invite: AuthEmailEvent = {
      kind: "invite.magicLink",
      recipient: "bob@example.com",
      url: "https://app.example.com/invite?wfs=tok2",
      expiresAt: 1_700_000_001_000,
      metadata: { roles: ["editor"] },
    };
    const mfa: AuthEmailEvent = {
      kind: "mfa.code",
      recipient: "carol@example.com",
      code: "123456",
      expiresAt: 1_700_000_002_000,
      username: "carol",
    };

    await sender.send(recovery);
    await sender.send(invite);
    await sender.send(mfa);

    expect(sent).toHaveLength(3);
    const kinds: AuthEmailKind[] = sent.map((e) => e.kind);
    expect(kinds).toEqual(["recovery.magicLink", "invite.magicLink", "mfa.code"]);
    expect(sent[0]?.url).toBe("https://app.example.com/reset?wfs=tok1");
    expect(sent[2]?.code).toBe("123456");
    expect(sent[1]?.metadata?.roles).toEqual(["editor"]);
  });
});
