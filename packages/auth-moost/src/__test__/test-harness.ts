import { ArbacUserProvider } from "@aooth/arbac-moost";
import type { MoostHttp } from "@moostjs/event-http";
import { Injectable } from "moost";

import { useAuth } from "../auth.composables";

/** One in-process HTTP response, body parsed as JSON when it is JSON. */
export interface HarnessResponse {
  status: number;
  // oxlint-disable-next-line typescript/no-explicit-any
  body: any;
  setCookies: string[];
  response: Response | null;
}

/**
 * Bind an in-process requester to `http` (`MoostHttp.request`): `json`
 * becomes the body (with `content-type: application/json`), the response
 * body is parsed when it is JSON, and `Set-Cookie` lines are collected.
 */
export function requestVia(
  http: MoostHttp,
): (input: string, init?: RequestInit & { json?: unknown }) => Promise<HarnessResponse> {
  return async (input, init = {}) => {
    const { json, ...rest } = init;
    const headers = new Headers(rest.headers);
    let body = rest.body;
    if (json !== undefined) {
      body = JSON.stringify(json);
      if (!headers.has("content-type")) headers.set("content-type", "application/json");
    }
    const response = await http.request(input, { ...rest, headers, body });
    if (!response) return { status: 0, body: null, setCookies: [], response: null };
    const text = await response.text();
    let parsed: unknown = text;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      // not JSON; leave as text
    }
    return {
      status: response.status,
      body: parsed,
      setCookies: response.headers.getSetCookie?.() ?? [],
      response,
    };
  };
}

// Module-level user → roles map read by `TestArbacUserProvider`. A harness
// sets it (via `setTestArbacUserRoles`) BEFORE Moost initialises; the provider
// class is defined once at module scope so infact's class-keyed singleton
// stays stable across tests while every test sees its own map.
let activeUserRoles = new Map<string, string[]>();

/** Point the shared test `ArbacUserProvider` at this test's user → roles map. */
export function setTestArbacUserRoles(roles: Map<string, string[]>): void {
  activeUserRoles = roles;
}

/**
 * Test `ArbacUserProvider`: the user is the authenticated session's
 * (`useAuth().getUserId()`), roles come from the map passed to
 * {@link setTestArbacUserRoles}, attrs are empty.
 */
@Injectable()
export class TestArbacUserProvider extends ArbacUserProvider {
  override getUserId(): string {
    return useAuth().getUserId();
  }
  override getRoles(id: string): string[] {
    return activeUserRoles.get(id) ?? [];
  }
  override getAttrs(): object {
    return {};
  }
}
