import { render, screen, within } from "@testing-library/svelte";
import { describe, expect, it } from "vitest";
import type { DialogRequest } from "../lib/contracts";
import RequestContext from "./RequestContext.svelte";

type Probe = { rule_name?: string | null; command: string; reason?: string | null };
type Violation = {
  guard_id: string;
  summary: string;
  configured_feedback?: string | null;
  auditor_findings?: string | null;
  scope: string;
  failed_probes?: Probe[];
};

function violation(guardId: string, failedProbes?: Probe[], extra: Partial<Violation> = {}): Violation {
  const item: Violation = {
    guard_id: guardId,
    summary: `Guard '${guardId}' requires confirmation`,
    scope: "activation",
    ...extra,
  };
  if (failedProbes !== undefined) item.failed_probes = failedProbes;
  return item;
}

function guardFailures(violations: Violation[]): DialogRequest {
  return {
    schema: "arc.decision.dialog.request.v2",
    request_id: "req-probes",
    presentation_kind: "guard_failures",
    title: "Decision needed",
    scope: "exact tool call once",
    violations,
    authorizations: [],
    operation: null,
    bundle_fingerprint: "sha256:probes",
    expires_at_unix_ms: 0,
  } as unknown as DialogRequest;
}

/** The `<li>` of one failed guard, found through the guard id `<code>` that opens it. */
function guardItem(guardId: string): HTMLElement {
  const guards = screen.getByRole("list", { name: "Failed guards" });
  const item = Array.from(guards.children).find(
    (child) => child.tagName === "LI" && child.querySelector("code")?.textContent === guardId,
  );
  expect(item, `failed guard item for ${guardId}`).toBeDefined();
  return item as HTMLElement;
}

describe("RequestContext", () => {
  it("renders failed guards, required authorizations, and visible operation simultaneously for aggregate_decision", () => {
    const request: DialogRequest = {
      schema: "arc.decision.dialog.request.v2",
      request_id: "req-aggregate",
      presentation_kind: "aggregate_decision",
      title: "Confirm sensitive aggregate operation",
      scope: "exact tool call once",
      violations: [
        {
          guard_id: "guard-ask",
          summary: "Arc policy requires your decision before this operation can continue.",
          configured_feedback: "Review this operation before continuing.",
          auditor_findings: "The request did not authorize this operation.",
          scope: "activation",
        },
      ],
      authorizations: [
        {
          guard_id: "guard-auth",
          summary: "Authorization required",
          auditor_findings: "The auditor found no policy conflict.",
          operation_fingerprint: "sha256:operation",
        },
      ],
      operation: "Bash git push",
      bundle_fingerprint: "sha256:aggregate",
      expires_at_unix_ms: 0,
    };

    render(RequestContext, { request });

    expect(screen.getByRole("list", { name: "Failed guards" })).toHaveTextContent("guard-ask");
    expect(screen.getByRole("list", { name: "Required authorizations" })).toHaveTextContent("guard-auth");
    expect(screen.getByText("Configured feedback")).toBeVisible();
    expect(screen.getByText("Review this operation before continuing.")).toBeVisible();
    expect(screen.getAllByText("Auditor findings")).toHaveLength(2);
    expect(screen.getByText("The request did not authorize this operation.")).toBeVisible();
    expect(screen.getByText("The auditor found no policy conflict.")).toBeVisible();
    expect(screen.getAllByText(/Authorization required/)).toHaveLength(1);
    expect(screen.queryByText(/Agent verdict:/)).toBeNull();
    expect(screen.getByText("Bash git push")).toBeVisible();
  });
});

describe("REQ-001 RequestContext: failed probes", () => {
  it("shows the Failed probes label and a list under the guard with the rule name and the command", () => {
    render(RequestContext, {
      request: guardFailures([
        violation("guard-tests", [{ rule_name: "tests-green", command: "cargo test --all" }]),
      ]),
    });

    const item = guardItem("guard-tests");
    expect(within(item).getByText("Failed probes")).toBeVisible();
    const list = within(item).getByRole("list", { name: "Failed probes" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(1);
    expect(list).toHaveTextContent("tests-green");
    const command = within(list).getByText("cargo test --all");
    expect(command.tagName).toBe("CODE");
    expect(command).toBeVisible();
  });

  it("shows an inline probe as its command alone", () => {
    render(RequestContext, {
      request: guardFailures([violation("guard-inline", [{ command: "git status --porcelain" }])]),
    });

    const list = within(guardItem("guard-inline")).getByRole("list", { name: "Failed probes" });
    const entries = within(list).getAllByRole("listitem");
    expect(entries).toHaveLength(1);
    expect(entries[0]).toHaveTextContent(/^git status --porcelain$/);
  });

  it("shows an explicit null rule name and null reason as the command alone", () => {
    render(RequestContext, {
      request: guardFailures([
        violation("guard-nulls", [{ rule_name: null, command: "ls", reason: null }]),
      ]),
    });

    const list = within(guardItem("guard-nulls")).getByRole("list", { name: "Failed probes" });
    expect(within(list).getAllByRole("listitem")[0]).toHaveTextContent(/^ls$/);
  });

  it("shows the reason of a probe that failed through not", () => {
    render(RequestContext, {
      request: guardFailures([
        violation("guard-not", [
          {
            rule_name: "work-in-progress",
            command: "cat .wip",
            reason: "negated expression evaluated to true",
          },
        ]),
      ]),
    });

    const list = within(guardItem("guard-not")).getByRole("list", { name: "Failed probes" });
    expect(list).toHaveTextContent("work-in-progress");
    expect(within(list).getByText("cat .wip")).toBeVisible();
    expect(within(list).getByText(/negated expression evaluated to true/)).toBeVisible();
  });

  it("lists every probe of a guard and keeps each guard's probes under that guard only", () => {
    render(RequestContext, {
      request: guardFailures([
        violation("guard-one", [
          { rule_name: "rule-a", command: "check-a" },
          { command: "check-b" },
          { rule_name: "rule-c", command: "check-c" },
        ]),
        violation("guard-two", [{ command: "check-d" }]),
        violation("guard-three"),
      ]),
    });

    const one = within(guardItem("guard-one")).getByRole("list", { name: "Failed probes" });
    expect(within(one).getAllByRole("listitem")).toHaveLength(3);
    for (const command of ["check-a", "check-b", "check-c"]) {
      expect(within(one).getByText(command)).toBeVisible();
    }
    expect(within(one).queryByText("check-d")).toBeNull();

    const two = within(guardItem("guard-two")).getByRole("list", { name: "Failed probes" });
    expect(within(two).getAllByRole("listitem")).toHaveLength(1);
    expect(within(two).getByText("check-d")).toBeVisible();
    expect(within(two).queryByText("check-a")).toBeNull();

    expect(screen.getAllByRole("list", { name: "Failed probes" })).toHaveLength(2);
    expect(screen.getAllByText("Failed probes")).toHaveLength(2);
    expect(within(guardItem("guard-three")).queryByText("Failed probes")).toBeNull();
    expect(within(guardItem("guard-three")).queryByRole("list")).toBeNull();
  });

  it("keeps one entry per cause when two entries are identical", () => {
    render(RequestContext, {
      request: guardFailures([
        violation("guard-twice", [
          { rule_name: "repeat", command: "repeat-check" },
          { rule_name: "repeat", command: "repeat-check" },
        ]),
      ]),
    });

    const list = within(guardItem("guard-twice")).getByRole("list", { name: "Failed probes" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
  });

  it("shows no Failed probes list when the field is absent or empty, and findings display as before", () => {
    render(RequestContext, {
      request: guardFailures([
        violation("guard-decide", undefined, {
          configured_feedback: "Review before continuing.",
          auditor_findings: "The change skips the review step.",
        }),
        violation("guard-empty", []),
      ]),
    });

    expect(screen.queryByText("Failed probes")).toBeNull();
    expect(screen.queryByRole("list", { name: "Failed probes" })).toBeNull();
    const item = guardItem("guard-decide");
    expect(within(item).getByText("Configured feedback")).toBeVisible();
    expect(within(item).getByText("Review before continuing.")).toBeVisible();
    expect(within(item).getByText("Auditor findings")).toBeVisible();
    expect(within(item).getByText("The change skips the review step.")).toBeVisible();
    expect(within(guardItem("guard-empty")).queryByRole("list")).toBeNull();
  });

  it("renders probe text as text, never as HTML", () => {
    const command = "echo <img src=x onerror=alert(1)> 2>/dev/null";
    const rule = "<b>bold-rule</b>";
    const reason = "<script>window.__probe_xss = 1</script>";
    const { container } = render(RequestContext, {
      request: guardFailures([violation("guard-xss", [{ rule_name: rule, command, reason }])]),
    });

    const list = within(guardItem("guard-xss")).getByRole("list", { name: "Failed probes" });
    expect(within(list).getByText(command)).toBeVisible();
    expect(list).toHaveTextContent(rule);
    expect(list).toHaveTextContent(reason);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect((window as unknown as Record<string, unknown>).__probe_xss).toBeUndefined();
    expect(list.innerHTML).toContain("&lt;img");
  });

  it("does not show an expected value or an observed hash even when the payload carries one", () => {
    const leaky = {
      rule_name: "tests-green",
      command: "cargo test",
      expected_values: ["EXPECTED-VALUE-7731"],
      observed_sha256: "sha256:OBSERVED-HASH-9120",
    } as unknown as Probe;
    const { container } = render(RequestContext, {
      request: guardFailures([violation("guard-leak", [leaky])]),
    });

    expect(container.textContent).not.toContain("EXPECTED-VALUE-7731");
    expect(container.textContent).not.toContain("OBSERVED-HASH-9120");
    expect(within(guardItem("guard-leak")).getByText("cargo test")).toBeVisible();
  });

  it("lists failed probes the same way in an aggregate_decision, and not under authorizations", () => {
    const request = {
      schema: "arc.decision.dialog.request.v2",
      request_id: "req-aggregate-probes",
      presentation_kind: "aggregate_decision",
      title: "Confirm sensitive aggregate operation",
      scope: "exact tool call once",
      violations: [violation("guard-ask", [{ rule_name: "branch-is-feature", command: "git branch" }])],
      authorizations: [
        {
          guard_id: "guard-auth",
          summary: "Authorization required",
          operation_fingerprint: "sha256:operation",
        },
      ],
      operation: "Bash git push",
      bundle_fingerprint: "sha256:aggregate",
      expires_at_unix_ms: 0,
    } as unknown as DialogRequest;
    render(RequestContext, { request });

    const list = within(guardItem("guard-ask")).getByRole("list", { name: "Failed probes" });
    expect(list).toHaveTextContent("branch-is-feature");
    expect(within(list).getByText("git branch")).toBeVisible();
    const authorizations = screen.getByRole("list", { name: "Required authorizations" });
    expect(within(authorizations).queryByText("Failed probes")).toBeNull();
    expect(screen.getAllByRole("list", { name: "Failed guards" })).toHaveLength(1);
  });
});
