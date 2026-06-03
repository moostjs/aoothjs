import { describe, expect, it } from "vite-plus/test";

import {
  createAuthedFetch,
  type FetchFn,
  type MinimalRequestInit,
  type MinimalResponse,
} from "./index";

function res(status: number): MinimalResponse {
  return { ok: status >= 200 && status < 300, status };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/** Flush the microtask + macrotask queue so all in-flight requests settle. */
const tick = () => new Promise((r) => setTimeout(r, 0));

describe("createAuthedFetch", () => {
  it("forwards credentials and passes a success response straight through", async () => {
    const calls: Array<{ input: string | URL; init?: MinimalRequestInit }> = [];
    const fetchMock: FetchFn = async (input, init) => {
      calls.push({ input, init });
      return res(200);
    };

    const api = createAuthedFetch({ fetch: fetchMock });
    const r = await api("/api/me");

    expect(r.status).toBe(200);
    expect(calls).toHaveLength(1);
    expect(calls[0].init?.credentials).toBe("include");
  });

  it("lets the caller override the default credentials mode", async () => {
    const calls: MinimalRequestInit[] = [];
    const fetchMock: FetchFn = async (_input, init) => {
      calls.push(init ?? {});
      return res(200);
    };

    const api = createAuthedFetch({ fetch: fetchMock });
    await api("/x", { credentials: "omit" });

    expect(calls[0].credentials).toBe("omit");
  });

  it("does not refresh on non-matching statuses (e.g. 500)", async () => {
    let appCalls = 0;
    let refreshCalls = 0;
    const fetchMock: FetchFn = async (input) => {
      if (input === "/auth/refresh") {
        refreshCalls++;
        return res(200);
      }
      appCalls++;
      return res(500);
    };

    const api = createAuthedFetch({ fetch: fetchMock });
    const r = await api("/api/me");

    expect(r.status).toBe(500);
    expect(refreshCalls).toBe(0);
    expect(appCalls).toBe(1);
  });

  it("on 401 refreshes (default path) and retries the original request once", async () => {
    let appCalls = 0;
    let refreshPathSeen: string | URL | undefined;
    const fetchMock: FetchFn = async (input) => {
      if (input === "/auth/refresh") {
        refreshPathSeen = input;
        return res(200);
      }
      appCalls++;
      return res(appCalls === 1 ? 401 : 200);
    };

    const api = createAuthedFetch({ fetch: fetchMock });
    const r = await api("/api/me");

    expect(r.status).toBe(200);
    expect(refreshPathSeen).toBe("/auth/refresh");
    expect(appCalls).toBe(2); // original (401) + one retry (200)
  });

  it("single-flights the refresh across concurrent 401s", async () => {
    let appCalls = 0;
    let refreshCalls = 0;
    const gate = deferred<void>();
    const fetchMock: FetchFn = async (input) => {
      if (input === "/auth/refresh") {
        refreshCalls++;
        await gate.promise;
        return res(200);
      }
      appCalls++;
      return res(appCalls <= 3 ? 401 : 200); // 3 originals 401, retries 200
    };

    const api = createAuthedFetch({ fetch: fetchMock });
    const all = Promise.all([api("/a"), api("/b"), api("/c")]);

    await tick(); // all three originals 401 and converge on one in-flight refresh
    expect(refreshCalls).toBe(1);
    gate.resolve();

    const results = await all;
    expect(results.map((r) => r.status)).toEqual([200, 200, 200]);
    expect(refreshCalls).toBe(1); // exactly one refresh for N concurrent 401s
    expect(appCalls).toBe(6); // 3 originals + 3 retries
  });

  it("calls onLogout exactly once when the refresh response is not OK and does not retry", async () => {
    let appCalls = 0;
    let refreshCalls = 0;
    let logoutCount = 0;
    const fetchMock: FetchFn = async (input) => {
      if (input === "/auth/refresh") {
        refreshCalls++;
        return res(401);
      }
      appCalls++;
      return res(401);
    };

    const api = createAuthedFetch({ fetch: fetchMock, onLogout: () => logoutCount++ });
    const r = await api("/api/me");

    expect(r.status).toBe(401); // original failing response surfaced
    expect(refreshCalls).toBe(1);
    expect(appCalls).toBe(1); // no retry
    expect(logoutCount).toBe(1);
  });

  it("fires onLogout once even when many concurrent requests fail to refresh", async () => {
    let refreshCalls = 0;
    let logoutCount = 0;
    const gate = deferred<void>();
    const fetchMock: FetchFn = async (input) => {
      if (input === "/auth/refresh") {
        refreshCalls++;
        await gate.promise;
        return res(401);
      }
      return res(401);
    };

    const api = createAuthedFetch({ fetch: fetchMock, onLogout: () => logoutCount++ });
    const all = Promise.all([api("/a"), api("/b"), api("/c")]);
    await tick();
    gate.resolve();
    const results = await all;

    expect(results.map((r) => r.status)).toEqual([401, 401, 401]);
    expect(refreshCalls).toBe(1);
    expect(logoutCount).toBe(1);
  });

  it("treats a refresh network error as a failed refresh (onLogout once, no retry)", async () => {
    let appCalls = 0;
    let logoutCount = 0;
    const fetchMock: FetchFn = async (input) => {
      if (input === "/auth/refresh") throw new Error("network down");
      appCalls++;
      return res(401);
    };

    const api = createAuthedFetch({ fetch: fetchMock, onLogout: () => logoutCount++ });
    const r = await api("/api/me");

    expect(r.status).toBe(401);
    expect(appCalls).toBe(1);
    expect(logoutCount).toBe(1);
  });

  it("retries only once — a still-401 retry is returned without a refresh storm", async () => {
    let refreshCalls = 0;
    const fetchMock: FetchFn = async (input) => {
      if (input === "/auth/refresh") {
        refreshCalls++;
        return res(200); // refresh succeeds
      }
      return res(401); // app keeps 401 even after the retry
    };

    const api = createAuthedFetch({ fetch: fetchMock });
    const r = await api("/api/me");

    expect(r.status).toBe(401);
    expect(refreshCalls).toBe(1); // the retry never re-enters refresh
  });

  it("honors a custom refreshPath and refreshOn status set", async () => {
    let appCalls = 0;
    let refreshPathSeen: string | URL | undefined;
    const fetchMock: FetchFn = async (input) => {
      if (input === "/api/auth/refresh") {
        refreshPathSeen = input;
        return res(200);
      }
      appCalls++;
      return res(appCalls === 1 ? 419 : 200);
    };

    const api = createAuthedFetch({
      fetch: fetchMock,
      refreshPath: "/api/auth/refresh",
      refreshOn: [419],
    });
    const r = await api("/api/me");

    expect(r.status).toBe(200);
    expect(refreshPathSeen).toBe("/api/auth/refresh");
    expect(appCalls).toBe(2);
  });
});
