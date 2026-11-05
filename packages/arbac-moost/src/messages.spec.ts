import { afterEach, describe, expect, it } from "vite-plus/test";

import { HttpError } from "@moostjs/event-http";
import { createEventContext, useLocale } from "@wooksjs/event-core";
import { setTranslator, translateErrorBody, useTranslation } from "moost";

import { insufficientPrivileges } from "./arbac.evaluate";
import { enforceControlsPolicy } from "./db/as-arbac-db-controller";
import { ARBAC_MESSAGES } from "./messages";

const quiet = { info() {}, warn() {}, error() {}, debug() {}, log() {} };

function inLocale<R>(locale: string, fn: () => R): R {
  return createEventContext({ logger: quiet }, () => {
    useLocale().set(locale);
    return fn();
  });
}

function thrown(fn: () => unknown): HttpError {
  try {
    fn();
  } catch (error) {
    return error as HttpError;
  }
  throw new Error("expected a throw");
}

afterEach(() => {
  setTranslator(undefined);
});

describe("ARBAC_MESSAGES", () => {
  it("ARBAC 403s carry code and params next to the English text", () => {
    expect(insufficientPrivileges("docs", "read").body).toMatchObject({
      statusCode: 403,
      code: "INSUFFICIENT_PRIVILEGES",
      params: { resource: "docs", action: "read" },
      message: 'Insufficient privileges for action "read" on resource "docs"',
    });
    expect(
      thrown(() => enforceControlsPolicy({ $with: false }, { $with: [{ name: "c" }] })).body,
    ).toMatchObject({
      code: "CONTROL_NOT_ALLOWED",
      params: { control: "$with" },
      message: 'Control "$with" is not allowed for your role',
    });
    expect(
      thrown(() => enforceControlsPolicy({ $groupBy: ["a"] }, { $groupBy: ["b"] })).body,
    ).toMatchObject({
      code: "CONTROL_VALUE_NOT_ALLOWED",
      params: { control: "$groupBy", value: "b" },
      message: 'Control "$groupBy=b" is not allowed for your role',
    });
  });

  it("is registered with moost on import and translated by code", () => {
    setTranslator({
      en: {},
      de: { CONTROL_NOT_ALLOWED: 'Steuerung "{control}" ist für Ihre Rolle nicht erlaubt' },
    });
    inLocale("de", () => {
      expect(useTranslation()?.messages()).toMatchObject({
        CONTROL_NOT_ALLOWED: 'Steuerung "{control}" ist für Ihre Rolle nicht erlaubt',
      });
      const body = thrown(() => enforceControlsPolicy({ $sort: false }, { $sort: { a: 1 } })).body;
      expect(translateErrorBody(body).message).toBe(
        'Steuerung "$sort" ist für Ihre Rolle nicht erlaubt',
      );
    });
    expect(Object.keys(ARBAC_MESSAGES)).toContain("ROW_OUT_OF_SCOPE");
  });
});
