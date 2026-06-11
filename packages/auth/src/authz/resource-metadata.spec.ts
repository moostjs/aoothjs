import { describe, expect, it } from "vite-plus/test";

import {
  buildProtectedResourceMetadata,
  buildWwwAuthenticateBearerChallenge,
} from "./resource-metadata";

describe("buildProtectedResourceMetadata", () => {
  it("defaults bearer_methods_supported to header presentation", () => {
    const doc = buildProtectedResourceMetadata({
      resource: "https://api.example/mcp",
      authorizationServers: ["https://x/auth"],
    });
    expect(doc.resource).toBe("https://api.example/mcp");
    expect(doc.authorization_servers).toEqual(["https://x/auth"]);
    expect(doc.bearer_methods_supported).toEqual(["header"]);
  });

  it("strips trailing slashes from authorization_servers (issuer exactness)", () => {
    const doc = buildProtectedResourceMetadata({
      resource: "https://api.example/mcp",
      authorizationServers: ["https://x/auth/", "https://y"],
    });
    expect(doc.authorization_servers).toEqual(["https://x/auth", "https://y"]);
  });

  it("omits optional fields entirely when not configured", () => {
    const doc = buildProtectedResourceMetadata({
      resource: "https://api.example/mcp",
      authorizationServers: ["https://x/auth"],
    });
    expect(doc).not.toHaveProperty("scopes_supported");
    expect(doc).not.toHaveProperty("resource_name");
  });

  it("emits optional fields and a custom bearer-methods list when configured", () => {
    const doc = buildProtectedResourceMetadata({
      resource: "https://api.example/mcp",
      authorizationServers: ["https://x/auth"],
      scopesSupported: ["mcp"],
      bearerMethodsSupported: ["header", "body"],
      resourceName: "Example MCP server",
    });
    expect(doc.scopes_supported).toEqual(["mcp"]);
    expect(doc.bearer_methods_supported).toEqual(["header", "body"]);
    expect(doc.resource_name).toBe("Example MCP server");
  });
});

describe("buildWwwAuthenticateBearerChallenge", () => {
  it("degrades to the bare scheme when no params are given", () => {
    expect(buildWwwAuthenticateBearerChallenge()).toBe("Bearer");
    expect(buildWwwAuthenticateBearerChallenge({})).toBe("Bearer");
  });

  it("emits every param quoted, in the fixed order", () => {
    const value = buildWwwAuthenticateBearerChallenge({
      scope: "mcp",
      resourceMetadataUrl: "https://api.example/.well-known/oauth-protected-resource",
      errorDescription: "token expired",
      error: "invalid_token",
      realm: "api",
    });
    expect(value).toBe(
      'Bearer realm="api", error="invalid_token", error_description="token expired", ' +
        'resource_metadata="https://api.example/.well-known/oauth-protected-resource", scope="mcp"',
    );
  });

  it("emits a single param alone", () => {
    expect(
      buildWwwAuthenticateBearerChallenge({ resourceMetadataUrl: "https://x/.well-known/prm" }),
    ).toBe('Bearer resource_metadata="https://x/.well-known/prm"');
  });

  it("backslash-escapes quotes and backslashes (RFC 7235 quoted-string)", () => {
    const value = buildWwwAuthenticateBearerChallenge({
      errorDescription: 'say "hi" \\ done',
    });
    expect(value).toBe('Bearer error_description="say \\"hi\\" \\\\ done"');
  });

  it("strips CR/LF and all other control chars (header-injection defense)", () => {
    const value = buildWwwAuthenticateBearerChallenge({
      error: "bad\r\nSet-Cookie: x=1",
    });
    expect(value).toBe('Bearer error="badSet-Cookie: x=1"');

    const swept = buildWwwAuthenticateBearerChallenge({
      realm: "a\u0000b\u0007c\u001Fd\u007Fe",
    });
    expect(swept).toBe('Bearer realm="abcde"');
  });
});
