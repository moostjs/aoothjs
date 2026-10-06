// `resolveQuery` (moost-db 0.1.149): an app command reads ANOTHER controller's
// rows as a READ of it for the current caller. Under ARBAC the read child
// evaluates the caller's grant on the target resource's `query` handler: the
// command's own grant is irrelevant to it, and the command's own scopes
// neither leak into the read nor change after it.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { bootIssues, createIssueSpace, type IssueSpace } from "./issue-actions-harness";

let space: IssueSpace;
beforeAll(async () => {
  space = await createIssueSpace();
});
afterAll(() => space.close());
beforeEach(() => space.seed());

// Region eu: 1, 2, 4; us: 3, 5. Titles: "alpha one", "alpha two", "beta three", "beta four", "gamma five".

const pick = (body: Record<string, unknown>) => body;
const ids = (body: any): number[] => body.rows.map((r: { id: number }) => r.id);

describe("resolveQuery under ARBAC", () => {
  it("an unrelated command reads only the rows the caller's read scope allows", async () => {
    const { send } = await bootIssues(["reader-eu", "tooler"]);
    const res = await send("POST", "/tools/pick", pick({ q: "" }));
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(ids(res.body)).toEqual([1, 2, 4]);
  });

  it("the command's own grant is irrelevant: no `tools` grant is needed by the read", async () => {
    // Reads everything via a grant of the issues resource; the command's own
    // scope (region us) does not narrow it.
    const { send } = await bootIssues(["lead", "tooler"]);
    expect(ids((await send("POST", "/tools/pick", pick({ q: "" }))).body)).toEqual([1, 2, 3, 4, 5]);
  });

  it("action-only caller (no read grant on the target): 403", async () => {
    const { send } = await bootIssues(["triage-eu", "tooler"]);
    const res = await send("POST", "/tools/pick", pick({ q: "" }));
    expect(res.status).toBe(403);
  });

  it("no identity-bearing read grant at all: 403", async () => {
    const { send } = await bootIssues(["tooler"]);
    expect((await send("POST", "/tools/pick", pick({ q: "" }))).status).toBe(403);
  });

  it("a projection hiding the searchable field: $search is 400 TARGET_INVALID", async () => {
    const { send } = await bootIssues(["reader-notitle", "tooler"]);
    const res = await send("POST", "/tools/pick", pick({ q: "$search=alpha" }));
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(JSON.stringify(res.body)).toContain("TARGET_INVALID");
    // Same through the envelope.
    const env = await send("POST", "/tools/pick", pick({ q: { q: "$search=alpha" } }));
    expect(env.status).toBe(400);
  });

  it("a projection hiding a field: selecting it is 400 Unknown field", async () => {
    const { send } = await bootIssues(["reader-notitle", "tooler"]);
    const res = await send("POST", "/tools/pick", pick({ q: "", select: ["title"] }));
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(JSON.stringify(res.body)).toContain("Unknown field");
    // A visible field is fine.
    const ok = await send("POST", "/tools/pick", pick({ q: "", select: ["status"] }));
    expect(ok.status).toBe(201);
    expect(ids(ok.body)).toEqual([1, 2, 3, 4, 5]);
  });

  it("`scope` narrows the read (ANDed in)", async () => {
    const { send } = await bootIssues(["reader-eu", "tooler"]);
    const res = await send("POST", "/tools/pick", pick({ q: "", scope: { status: "open" } }));
    expect(ids(res.body)).toEqual([1, 2]);
    // It narrows, never widens: another region stays out of reach.
    const wide = await send("POST", "/tools/pick", pick({ q: "", scope: { region: "us" } }));
    expect(ids(wide.body)).toEqual([]);
  });

  it("an attenuated credential narrows what the command reads", async () => {
    const { send, user } = await bootIssues(["lead", "reader-eu", "tooler"]);
    const run = () => send("POST", "/tools/pick", pick({ q: "" }));
    expect(ids((await run()).body)).toEqual([1, 2, 3, 4, 5]);
    user.attenuation = { roles: ["reader-eu", "tooler"] };
    expect(ids((await run()).body)).toEqual([1, 2, 4]);
  });

  it("the caller's own scopes do not leak into the read and are unchanged after it", async () => {
    // `tooler` is scoped to region "us" on `tools.pick`; the read of issues
    // is `lead`'s (every region). The us scope must not narrow the read.
    const { send } = await bootIssues(["lead", "tooler"]);
    const res = await send("POST", "/tools/pick", pick({ q: "" }));
    expect(ids(res.body)).toEqual([1, 2, 3, 4, 5]);
    expect(res.body.before).toEqual([{ filter: { region: "us" } }]);
    expect(res.body.after).toEqual(res.body.before);
  });
});
