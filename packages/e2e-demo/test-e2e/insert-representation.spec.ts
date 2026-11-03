import { expect, test } from "@playwright/test";

import { bearerAuth, mintToken, rows } from "./harness";

/**
 * `Prefer: return=representation` on an ARBAC DB controller that opts in
 * (`CommentsController`): the insert answers the stored row as `row`, read
 * back under the caller's comments READ grant — exactly `GET /one/:id`.
 * Additive only (one comment per test), so the suite needs no reset.
 */
test.describe("INSERT-REPR: insert read-back under the read grant", () => {
  test("INSERT-REPR-001: a member gets the stored comment, equal to GET /one/:id", async ({
    request,
  }) => {
    const bob = await mintToken(request, "t1_bob"); // member: own comments, tenant-scoped reads
    const [task] = await rows(request, bob, "/tasks/query?$select=id&$limit=1");
    const res = await request.post("/comments", {
      headers: { ...bearerAuth(bob), Prefer: "return=representation" },
      data: { taskId: task.id, body: "insert-repr-001" },
    });
    expect(res.status()).toBe(201);
    expect(res.headers()["preference-applied"]).toBe("return=representation");
    const body = (await res.json()) as { insertedId: string; row: Record<string, unknown> };
    expect(body.row).toMatchObject({
      id: body.insertedId,
      taskId: task.id,
      body: "insert-repr-001",
      authorUsername: "t1_bob",
    });
    expect(typeof body.row.createdAt).toBe("number");
    const one = await request.get(`/comments/one/${body.insertedId}`, {
      headers: bearerAuth(bob),
    });
    expect(one.status()).toBe(200);
    expect(body.row).toEqual(await one.json());
  });

  test("INSERT-REPR-002: without the header the insert answers the plain result", async ({
    request,
  }) => {
    const bob = await mintToken(request, "t1_bob");
    const [task] = await rows(request, bob, "/tasks/query?$select=id&$limit=1");
    const res = await request.post("/comments", {
      headers: bearerAuth(bob),
      data: { taskId: task.id, body: "insert-repr-002" },
    });
    expect(res.status()).toBe(201);
    expect(res.headers()["preference-applied"]).toBeUndefined();
    expect(Object.keys(await res.json())).toEqual(["insertedId"]);
  });
});
