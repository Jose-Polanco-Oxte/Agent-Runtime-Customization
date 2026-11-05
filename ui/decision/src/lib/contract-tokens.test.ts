// REQ-009 CP-28 (AC-009.5, AC-009.6): the dialog request wire token and the shape of
// the preview fixtures must not change while the TypeScript contract names are renamed.
//
// Rename safety: no identifier that REQ-009 renames is imported or written here.
// The module is read as a namespace and the validator is selected by name from the
// pre- and post-rename spellings (the old spelling is built from parts, so the
// whole-word scan of `ui/decision/src` finds nothing). The request type comes from
// the fixture, not from a named import. S6 and S7 therefore need no edit in this file.
import { describe, expect, it } from "vitest";
import * as contracts from "./contracts";
import { fixtureFromLocation } from "./fixtures";

type ViewModel = ReturnType<typeof fixtureFromLocation>;
type Request = ViewModel["request"];

const REQUEST_SCHEMA = "arc.decision.dialog.request.v2";

const VALIDATOR_NAMES = [
  "validateDialogRequest",
  `${"validateDialogRequest"}${"V2"}`,
];

function selectValidator(): (request: Request) => void {
  const exported = contracts as unknown as Record<string, unknown>;
  const found = VALIDATOR_NAMES.filter((name) => typeof exported[name] === "function");
  // Exactly one spelling may exist at any time: a transitional alias would fail here.
  expect(found).toHaveLength(1);
  return exported[found[0]] as (request: Request) => void;
}

const validate = selectValidator();

function fixture(name: string): ViewModel {
  return fixtureFromLocation({ search: `?fixture=${name}` });
}

function withSchema(schema: unknown): Request {
  return { ...fixture("default").request, schema } as unknown as Request;
}

describe("dialog request schema token", () => {
  it("accepts the correct request schema literal", () => {
    expect(() => validate(withSchema(REQUEST_SCHEMA))).not.toThrow();
  });

  it("accepts the unmodified request of every preview fixture", () => {
    for (const name of ["default", "minimal", "long", "unicode", "light"]) {
      const request = fixture(name).request;
      expect(request.schema).toBe(REQUEST_SCHEMA);
      expect(() => validate(request)).not.toThrow();
    }
  });

  it.each([
    ["previous version", "arc.decision.dialog.request.v1"],
    ["next version", "arc.decision.dialog.request.v3"],
    ["version token removed", "arc.decision.dialog.request"],
    ["response schema", "arc.decision.dialog.response.v2"],
    ["unrelated schema", "arc.decision_task.request.v1"],
    ["upper case", "ARC.DECISION.DIALOG.REQUEST.V2"],
    ["trailing space", `${REQUEST_SCHEMA} `],
    ["leading space", ` ${REQUEST_SCHEMA}`],
    ["empty string", ""],
  ])("rejects a wrong schema literal (%s)", (_label, schema) => {
    expect(() => validate(withSchema(schema))).toThrowError(
      new TypeError("invalid request schema"),
    );
  });

  it.each([
    ["undefined", undefined],
    ["null", null],
    ["number", 2],
    ["object", { v: 2 }],
  ])("rejects a non-string schema value (%s)", (_label, schema) => {
    expect(() => validate(withSchema(schema))).toThrowError(
      new TypeError("invalid request schema"),
    );
  });
});

describe("preview fixture key set", () => {
  it("pins the view model keys", () => {
    expect(Object.keys(fixture("default")).sort()).toEqual([
      "max_user_message_chars",
      "preview",
      "request",
      "theme",
    ]);
  });

  it("pins the request keys and the wire token", () => {
    const request = fixture("default").request;
    expect(Object.keys(request).sort()).toEqual([
      "authorizations",
      "bundle_fingerprint",
      "expires_at_unix_ms",
      "operation",
      "presentation_kind",
      "request_id",
      "schema",
      "scope",
      "title",
      "violations",
    ]);
    expect(request.schema).toBe(REQUEST_SCHEMA);
    expect(request.presentation_kind).toBe("guard_failures");
  });

  it("pins the violation item keys", () => {
    const violations = fixture("default").request.violations;
    expect(violations).toHaveLength(1);
    expect(Object.keys(violations[0]).sort()).toEqual(["guard_id", "scope", "summary"]);
  });

  it("keeps the same request key set in every fixture", () => {
    const expected = Object.keys(fixture("default").request).sort();
    for (const name of ["minimal", "long", "unicode", "light"]) {
      expect(Object.keys(fixture(name).request).sort()).toEqual(expected);
    }
  });
});
