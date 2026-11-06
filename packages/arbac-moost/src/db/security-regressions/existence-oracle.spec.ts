// No existence oracle: every id-addressed path answers a row outside the
// caller's scope exactly like a row that does not exist — same status, same
// body (incl. `code` / `message` and its translation) and same headers, with
// and without a translator registered. Each case runs the path twice (a
// missing id, an out-of-scope id) on a freshly seeded table and compares the
// whole response. Echoed ids are normalised (a 'rows' action names the ids it
// refused — the ids the client sent).
import { allowTableAction, allowTableWrite, defineRole } from "@aooth/arbac";
import { DbAction, DbActionID, InputForm, TableController } from "@atscript/moost-db";
import { type MoostHttp, Post } from "@moostjs/event-http";
import { clearGlobalWooks, setTranslator } from "moost";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { bootArbacHttp } from "../../__testing__/arbac-http";
import { FakeUserProvider } from "../../__testing__/user-provider";
import { ArbacAction, ArbacResource } from "../../arbac.decorator";
import { MoostArbac } from "../../moost-arbac";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { WrDoc, WrNote, WrSignForm, WrUser } from "../write-fixtures.as";
import { bootIssues, createIssueSpace, type IssueSpace } from "./issue-actions-harness";
import { createSpace, type Harness, wipe } from "./relations-harness";

type Req = [method: string, path: string, body?: unknown];
/** A path under test: its name, the caller's roles, its request for an id. */
type Case = [name: string, roles: string[], req: (id: number) => Req];

interface Answer {
  status: number;
  headers: Record<string, string>;
  text: string;
}

/**
 * A request, answered as status + its headers + the body text with `id`
 * masked (`date` dropped; `content-length` too — the masked body stands for it).
 */
async function answer(
  http: MoostHttp,
  locale: string | undefined,
  [method, path, body]: Req,
  id: number,
): Promise<Answer> {
  const headers: Record<string, string> = locale ? { "accept-language": locale } : {};
  if (body !== undefined) headers["content-type"] = "application/json";
  const res = (await http.request(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  }))!;
  const out: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    if (k !== "date" && k !== "content-length") out[k] = v;
  });
  const text = (await res.text()).replaceAll(`"id":${id}`, '"id":"ID"');
  return { status: res.status, headers: out, text };
}

/**
 * Asks `req` for the `missing` id, reseeds, then for the `foreign` (out-of-scope)
 * id: both answers must be identical.
 */
async function expectSameAnswer(
  http: MoostHttp,
  locale: string | undefined,
  req: Case[2],
  [missing, foreign]: [number, number],
  reseed: () => Promise<void>,
): Promise<void> {
  useTranslatorFor(locale);
  const a = await answer(http, locale, req(missing), missing);
  await reseed();
  expect(await answer(http, locale, req(foreign), foreign)).toEqual(a);
}

/** `undefined` = no translator; else a gettext-style one that marks every text it translates. */
const LOCALES = [undefined, "xx"] as const;

function useTranslatorFor(locale: string | undefined): void {
  if (locale) setTranslator((text) => `«${text}»`, { locales: ["en", locale] });
}

afterEach(() => setTranslator(undefined));

// ── CRUD, `/one`, `/meta/actions` and an @DbActionID handler ─────────────────

const tenantA = (extra: ArbacDbScope = {}) => ({ filter: { tenant: "a" }, ...extra });
const ROLES = [
  defineRole<object, ArbacDbScope>()
    .id("rw")
    .use(
      allowTableWrite("ox-docs", { scope: () => tenantA() }),
      allowTableAction("ox-docs", ["doc.sign"], { scope: () => tenantA() }),
    )
    .build(),
  defineRole<object, ArbacDbScope>()
    .id("rw-nested")
    .use(allowTableWrite("ox-docs", { scope: () => tenantA({ nestedWrites: ["notes"] }) }))
    .build(),
];

@TableController(WrDoc, "ox-docs")
@ArbacResource("ox-docs")
class OxDocsController extends AsArbacDbController<typeof WrDoc> {
  @Post("actions/sign")
  @DbAction("sign", { label: "sign" })
  @ArbacAction("doc.sign")
  sign(@DbActionID() id: unknown, @InputForm(WrSignForm) input: unknown) {
    return { id, input };
  }
}

async function boot(roles: string[]): Promise<MoostHttp> {
  clearGlobalWooks();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  for (const r of ROLES) arbac.registerRole(r);
  return bootArbacHttp({
    arbac,
    user: new FakeUserProvider("u1", roles),
    controllers: [OxDocsController],
    authorize: true,
  });
}

describe("tenant-scoped table: missing (99) vs other tenant's row (2)", () => {
  let space: Harness;

  beforeAll(async () => {
    space = await createSpace([WrUser, WrDoc, WrNote]);
  });
  afterAll(() => space.close());

  async function reseed(): Promise<void> {
    wipe(space, [WrNote, WrDoc, WrUser]);
    await space.table(WrUser).insertMany([
      { id: 1, name: "alice", tenant: "a" },
      { id: 2, name: "bob", tenant: "b" },
    ]);
    await space.table(WrDoc).insertMany([
      { id: 1, title: "a1", tenant: "a", status: "open" },
      { id: 2, title: "b1", tenant: "b", status: "open", ownerId: 2 },
    ]);
    await space.table(WrNote).insertMany([
      { id: 1, body: "n1", tenant: "a", docId: 1 },
      { id: 2, body: "n2", tenant: "b", docId: 2 },
    ]);
  }

  beforeEach(reseed);

  const PATHS: Case[] = [
    ["GET /one/:id", ["rw"], (id) => ["GET", `/ox-docs/one/${id}`]],
    ["GET /one?id=", ["rw"], (id) => ["GET", `/ox-docs/one?id=${id}`]],
    ["GET /query?id=", ["rw"], (id) => ["GET", `/ox-docs/query?id=${id}`]],
    ["GET /pages?id=", ["rw"], (id) => ["GET", `/ox-docs/pages?id=${id}`]],
    ["GET /meta/actions/:id", ["rw"], (id) => ["GET", `/ox-docs/meta/actions/${id}`]],
    ["GET /meta/actions?id=", ["rw"], (id) => ["GET", `/ox-docs/meta/actions?id=${id}`]],
    ["PATCH", ["rw"], (id) => ["PATCH", "/ox-docs", { id, title: "x" }]],
    ["PATCH with version", ["rw"], (id) => ["PATCH", "/ox-docs", { id, version: 1, title: "x" }]],
    ["PATCH stale version", ["rw"], (id) => ["PATCH", "/ox-docs", { id, version: 7, title: "x" }]],
    [
      "PATCH bulk",
      ["rw"],
      (id) => [
        "PATCH",
        "/ox-docs",
        [
          { id: 1, title: "x" },
          { id, title: "x" },
        ],
      ],
    ],
    [
      "PATCH nested",
      ["rw-nested"],
      (id) => ["PATCH", "/ox-docs", { id, notes: { $update: [{ id: 2, body: "x" }] } }],
    ],
    ["PUT", ["rw"], (id) => ["PUT", "/ox-docs", { id, title: "x", tenant: "a" }]],
    [
      "PUT stale version",
      ["rw"],
      (id) => ["PUT", "/ox-docs", { id, version: 7, title: "x", tenant: "a" }],
    ],
    [
      "PUT bulk",
      ["rw"],
      (id) => [
        "PUT",
        "/ox-docs",
        [
          { id: 1, title: "x", tenant: "a" },
          { id, title: "x", tenant: "a" },
        ],
      ],
    ],
    ["DELETE /:id", ["rw"], (id) => ["DELETE", `/ox-docs/${id}`]],
    ["DELETE ?id=", ["rw"], (id) => ["DELETE", `/ox-docs?id=${id}`]],
    [
      "@DbActionID action",
      ["rw"],
      (id) => ["POST", "/ox-docs/actions/sign", { ids: { id }, input: { note: "x" } }],
    ],
  ];

  describe.each(LOCALES)("translator locale: %s", (locale) => {
    it.each(PATHS)("%s", async (_name, roles, req) => {
      await expectSameAnswer(await boot(roles), locale, req, [99, 2], reseed);
      // Nothing written to the other tenant's row.
      expect(await space.table(WrDoc).findOne({ filter: { id: 2 }, controls: {} })).toMatchObject({
        title: "b1",
        tenant: "b",
      });
    });
  });
});

// ── Row actions, query targets and a view's delegated actions ───────────────

describe("region-scoped actions: missing (99) vs out-of-scope issue (3)", () => {
  let space: IssueSpace;
  beforeAll(async () => {
    space = await createIssueSpace();
  });
  afterAll(() => space.close());
  beforeEach(() => space.seed());

  // Region eu: issues 1, 2, 4; issue 3 is region us.
  const PATHS: Case[] = [
    ["GET /one/:id", ["reader-eu"], (id) => ["GET", `/issues/one/${id}`]],
    ["'row' action", ["triage-eu"], (id) => ["POST", "/issues/actions/resolve", { ids: { id } }]],
    ["'rows' action", ["triage-eu"], (id) => ["POST", "/issues/actions/close", { ids: [{ id }] }]],
    [
      "'rows' action, mixed with an in-scope id",
      ["triage-eu"],
      (id) => ["POST", "/issues/actions/close", { ids: [{ id: 1 }, { id }] }],
    ],
    [
      "query target",
      ["reader-eu", "closer"],
      (id) => ["POST", "/issues/actions/close", { query: { q: `id=${id}` } }],
    ],
    [
      "query target, dry run",
      ["reader-eu", "closer"],
      (id) => ["POST", "/issues/actions/close", { query: { q: `id=${id}`, dryRun: true } }],
    ],
    ["GET /meta/actions/:id", ["triage-eu"], (id) => ["GET", `/issues/meta/actions/${id}`]],
    [
      "view: GET /meta/actions?id= (delegated)",
      ["reader-eu", "triage-eu"],
      (id) => ["GET", `/board/meta/actions?id=${id}`],
    ],
    [
      "view: delegated query target",
      ["reader-eu", "triage-eu"],
      (id) => ["POST", "/board/delegated-actions/close", { query: { q: `id=${id}` } }],
    ],
    ["view: GET /one/:id", ["reader-eu"], (id) => ["GET", `/board/one/${id}`]],
  ];

  describe.each(LOCALES)("translator locale: %s", (locale) => {
    it.each(PATHS)("%s", async (_name, roles, req) => {
      const { http } = await bootIssues(roles);
      await expectSameAnswer(http, locale, req, [99, 3], () => space.seed());
      expect((await space.statuses())[3]).toBe("open");
    });
  });
});
