// REQ-010: TS side of the shared dialog contract fixture.
//
// tests/fixtures/dialog_contract.json is also read by tests/dialog_contract_fixture_tests.rs,
// where Rust (`read_dialog_request`, the host stdin boundary) is the reference. Every case
// here must get the same accept/reject outcome from the hand-written TS validators.
//
// Exports that REQ-010 adds to contracts.ts are read from the module namespace and asserted
// to exist inside each test, so this file compiles before they exist and fails by assertion.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import * as contracts from "./contracts";

type Outcome = "accept" | "reject";
type Node = Record<string, unknown>;

interface BoundaryCase {
  name: string;
  base: string;
  field: string;
  limit: string;
  offset: number;
  expect: Outcome;
}

/** REQ-001: `limits[limit] + offset` copies of `item` at `field`. */
interface CountCase {
  name: string;
  base: string;
  field: string;
  limit: string;
  offset: number;
  item: unknown;
  expect: Outcome;
}

interface RequestCase {
  name: string;
  base?: string;
  request?: unknown;
  set?: Record<string, unknown>;
  remove?: string[];
  expect: Outcome;
}

interface ViewModelCase {
  name: string;
  base?: string;
  request_set?: Record<string, unknown>;
  view?: Record<string, unknown>;
  view_remove?: string[];
  view_model?: unknown;
  expect: Outcome;
}

interface Fixture {
  limits: Record<string, number>;
  boundary_string: { astral: string; astral_count: number; fill: string };
  bases: Record<string, unknown>;
  boundary_cases: BoundaryCase[];
  count_cases: CountCase[];
  request_cases: RequestCase[];
  view_model_cases: ViewModelCase[];
}

const fixturePath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../tests/fixtures/dialog_contract.json",
);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as Fixture;

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function exported(name: string): (value: unknown) => unknown {
  const value = (contracts as unknown as Node)[name];
  expect(typeof value, `contracts.ts must export ${name}`).toBe("function");
  return value as (value: unknown) => unknown;
}

function parseDialogRequest(value: unknown): unknown {
  return exported("parseDialogRequest")(value);
}

function parseDecisionViewModel(value: unknown): unknown {
  return exported("parseDecisionViewModel")(value);
}

/** A validator rejects by throwing TypeError, the class `classifyFrontendError` maps to invalid_payload. */
function outcomeOf(run: () => unknown): Outcome {
  try {
    run();
    return "accept";
  } catch (error: unknown) {
    if (error instanceof TypeError) return "reject";
    throw error;
  }
}

/** astral_count astral code points followed by fill, `length` code points in total. */
function buildString(length: number): string {
  const { astral, astral_count: count, fill } = fixture.boundary_string;
  return astral.repeat(count) + fill.repeat(length - count);
}

function parent(root: unknown, segments: string[]): Node {
  let node = root as Node;
  for (const segment of segments) node = node[segment] as Node;
  return node;
}

function setPath(root: unknown, path: string, value: unknown): void {
  const segments = path.split(".");
  const last = segments.pop() as string;
  parent(root, segments)[last] = value;
}

function removePath(root: unknown, path: string): void {
  const segments = path.split(".");
  const last = segments.pop() as string;
  delete parent(root, segments)[last];
}

function baseRequest(name: string): unknown {
  return clone(fixture.bases[name]);
}

function requestOf(testCase: RequestCase): unknown {
  if (!("base" in testCase)) return clone(testCase.request);
  const request = baseRequest(testCase.base as string);
  for (const [path, value] of Object.entries(testCase.set ?? {})) setPath(request, path, clone(value));
  for (const path of testCase.remove ?? []) removePath(request, path);
  return request;
}

function boundaryRequestOf(testCase: BoundaryCase): unknown {
  const request = baseRequest(testCase.base);
  const length = fixture.limits[testCase.limit] + testCase.offset;
  setPath(request, testCase.field, buildString(length));
  return request;
}

function countRequestOf(testCase: CountCase): unknown {
  const request = baseRequest(testCase.base);
  const length = fixture.limits[testCase.limit] + testCase.offset;
  setPath(
    request,
    testCase.field,
    Array.from({ length }, () => clone(testCase.item)),
  );
  return request;
}

function viewModelOf(testCase: ViewModelCase): unknown {
  if ("view_model" in testCase) return clone(testCase.view_model);
  const request = baseRequest(testCase.base as string);
  for (const [path, value] of Object.entries(testCase.request_set ?? {})) {
    setPath(request, path, clone(value));
  }
  const model: Node = { request, ...clone(testCase.view) };
  for (const key of testCase.view_remove ?? []) delete model[key];
  return model;
}

describe("shared dialog contract fixture: limits", () => {
  it("exports TS limit constants equal to the fixture limits, which equal the Rust constants", () => {
    const limits = (contracts as unknown as Node)["DIALOG_LIMITS"];
    expect(limits, "contracts.ts must export DIALOG_LIMITS").toBeDefined();
    expect(limits).toEqual(fixture.limits);
  });

  it("builds boundary strings that UTF-16 length counting would miscount", () => {
    const { astral, astral_count: count } = fixture.boundary_string;
    expect(Array.from(astral)).toHaveLength(1);
    expect(astral.length).toBe(2);
    expect(count).toBeGreaterThanOrEqual(1);
    const text = buildString(fixture.limits.id);
    expect(Array.from(text)).toHaveLength(fixture.limits.id);
    expect(text.length).toBe(fixture.limits.id + count);
  });

  it("has a boundary pair for every limit and unique case names", () => {
    for (const limit of ["id", "title", "scope", "summary", "operation", "feedback", "findings"]) {
      for (const [offset, expected] of [[0, "accept"], [1, "reject"]] as const) {
        expect(
          fixture.boundary_cases.some(
            (c) => c.limit === limit && c.offset === offset && c.expect === expected,
          ),
          `boundary case for ${limit} offset ${offset}`,
        ).toBe(true);
      }
    }
    for (const list of [fixture.boundary_cases, fixture.request_cases, fixture.view_model_cases]) {
      const names = list.map((c) => c.name);
      expect(new Set(names).size).toBe(names.length);
    }
  });
});

describe("AC-010.1: validateDialogRequest enforces the Rust length limits", () => {
  const limited = fixture.boundary_cases.filter((c) => ["id", "title", "scope"].includes(c.limit));

  it.each(limited.map((c) => [c.name, c] as const))("%s", (_name, testCase) => {
    const request = boundaryRequestOf(testCase);
    const outcome = outcomeOf(() => contracts.validateDialogRequest(request as contracts.DialogRequest));
    expect(outcome).toBe(testCase.expect);
  });
});

describe("AC-010.2: validateDialogRequest rejects an unknown presentation kind at runtime", () => {
  it("throws a TypeError for a kind outside the closed set", () => {
    const request = baseRequest("guard_failures") as Node;
    request["presentation_kind"] = "bulk_decision";
    expect(() => contracts.validateDialogRequest(request as unknown as contracts.DialogRequest)).toThrow(
      TypeError,
    );
  });

  it("still accepts each known kind", () => {
    for (const name of Object.keys(fixture.bases)) {
      const request = baseRequest(name) as contracts.DialogRequest;
      expect(() => contracts.validateDialogRequest(request), name).not.toThrow();
    }
  });
});

describe("shared fixture: boundary cases through parseDialogRequest", () => {
  it.each(fixture.boundary_cases.map((c) => [c.name, c] as const))("%s", (_name, testCase) => {
    const request = boundaryRequestOf(testCase);
    expect(outcomeOf(() => parseDialogRequest(request))).toBe(testCase.expect);
  });
});

describe("REQ-001: failed_probes in the shared fixture", () => {
  it("pins the per-guard failed_probes limit at 64 and exports it", () => {
    expect(fixture.limits.failed_probes).toBe(64);
    const limits = (contracts as unknown as Node)["DIALOG_LIMITS"] as Record<string, number>;
    expect(limits.failed_probes).toBe(64);
  });

  it("has both sides of each count boundary for each kind and unique case names", () => {
    for (const kind of ["guard_failures", "aggregate_decision"]) {
      for (const [offset, expected] of [[0, "accept"], [1, "reject"]] as const) {
        expect(
          fixture.count_cases.some(
            (c) =>
              c.base === kind &&
              c.limit === "failed_probes" &&
              c.offset === offset &&
              c.expect === expected,
          ),
          `count case for ${kind} offset ${offset}`,
        ).toBe(true);
      }
    }
    const names = fixture.count_cases.map((c) => c.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it("has a boundary pair for the command, rule_name and reason of an entry", () => {
    for (const [field, limit] of [
      ["violations.0.failed_probes.0.command", "id"],
      ["violations.0.failed_probes.0.rule_name", "id"],
      ["violations.0.failed_probes.0.reason", "summary"],
    ] as const) {
      for (const [offset, expected] of [[0, "accept"], [1, "reject"]] as const) {
        expect(
          fixture.boundary_cases.some(
            (c) => c.field === field && c.limit === limit && c.offset === offset && c.expect === expected,
          ),
          `boundary case for ${field} offset ${offset}`,
        ).toBe(true);
      }
    }
  });

  it("builds count cases whose entries are all valid, so only the count can reject", () => {
    for (const testCase of fixture.count_cases) {
      const request = countRequestOf({ ...testCase, offset: 0 });
      expect(outcomeOf(() => parseDialogRequest(request)), testCase.name).toBe("accept");
    }
  });
});

describe("shared fixture: count cases through parseDialogRequest", () => {
  it.each(fixture.count_cases.map((c) => [c.name, c] as const))("%s", (_name, testCase) => {
    const request = countRequestOf(testCase);
    expect(outcomeOf(() => parseDialogRequest(request))).toBe(testCase.expect);
  });

  it.each(fixture.count_cases.map((c) => [c.name, c] as const))(
    "%s through validateDialogRequest",
    (_name, testCase) => {
      const request = countRequestOf(testCase);
      expect(
        outcomeOf(() => contracts.validateDialogRequest(request as contracts.DialogRequest)),
      ).toBe(testCase.expect);
    },
  );
});

describe("shared fixture: request cases through parseDialogRequest", () => {
  it.each(fixture.request_cases.map((c) => [c.name, c] as const))("%s", (_name, testCase) => {
    const request = requestOf(testCase);
    expect(outcomeOf(() => parseDialogRequest(request))).toBe(testCase.expect);
  });
});

describe("shared fixture: view model cases through parseDecisionViewModel", () => {
  it.each(fixture.view_model_cases.map((c) => [c.name, c] as const))("%s", (_name, testCase) => {
    const model = viewModelOf(testCase);
    expect(outcomeOf(() => parseDecisionViewModel(model))).toBe(testCase.expect);
  });
});

describe("AC-010.4: parseDialogRequest normalizes the optional operation", () => {
  it("returns operation null, not undefined, when the key is absent in a guard_failures request", () => {
    const request = baseRequest("guard_failures") as Node;
    delete request["operation"];
    expect("operation" in request).toBe(false);
    const parsed = parseDialogRequest(request) as Node;
    expect("operation" in parsed).toBe(true);
    expect(parsed["operation"]).toBeNull();
  });

  it("keeps an explicit null operation as null in a guard_failures request", () => {
    const parsed = parseDialogRequest(baseRequest("guard_failures")) as Node;
    expect(parsed["operation"]).toBeNull();
  });

  it("keeps a present operation string unchanged", () => {
    const request = baseRequest("guard_failures") as Node;
    request["operation"] = "ls -la";
    expect((parseDialogRequest(request) as Node)["operation"]).toBe("ls -la");
  });
});

describe("AC-010.4: the fixture keeps the Rust-only blank characters", () => {
  it.each([
    ["U+1680", "\u1680"],
    ["U+3000", "\u3000"],
  ])("rejects a title made only of %s, which Rust trim treats as whitespace", (_label, char) => {
    expect(fixture.request_cases.some((c) => c.set?.["title"] === char && c.expect === "reject")).toBe(true);
    const request = baseRequest("guard_failures") as Node;
    request["title"] = char;
    expect(outcomeOf(() => parseDialogRequest(request))).toBe("reject");
  });
});
