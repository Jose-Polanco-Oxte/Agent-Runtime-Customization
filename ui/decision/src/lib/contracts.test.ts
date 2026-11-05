import { describe, expect, it } from "vitest";
import { createDecisionBridge } from "./bridge";
import {
  DIALOG_LIMITS,
  boundUserMessage,
  classifyFrontendError,
  dialogGuardIds,
  parseDialogRequest,
  validateDialogRequest,
  optionalUserMessage,
} from "./contracts";
import { PreviewDecisionBridge } from "./preview-bridge";
import { TauriDecisionBridge } from "./tauri-bridge";
import type { DecisionViewModel } from "./contracts";

const viewModel: DecisionViewModel = {
  request: {
    schema: "arc.decision.dialog.request.v2",
    request_id: "request-test",
    presentation_kind: "guard_failures",
    title: "Decision",
    scope: "once",
    violations: [
      {
        guard_id: "test_guard",
        summary: "Literal text ✅",
        scope: "once",
      },
    ],
    authorizations: [],
    operation: null,
    bundle_fingerprint: "sha256:test-bundle",
    expires_at_unix_ms: 0,
  },
  theme: "dark",
  max_user_message_chars: 4,
  preview: true,
};

describe("decision UI contract helpers", () => {
  it("validates aggregated GuardFailures requests and exposes all guard IDs", () => {
    const request = {
      schema: "arc.decision.dialog.request.v2" as const,
      request_id: "request-v2",
      presentation_kind: "guard_failures" as const,
      title: "Guard failures",
      scope: "this activation",
      violations: [
        {
          guard_id: "guard-a",
          summary: "Tests are missing",
          configured_feedback: "Run the required checks before finishing.",
          auditor_findings: "The requested test suite did not run.",
          scope: "lifecycle:end",
        },
        { guard_id: "guard-b", summary: "Branch is protected", scope: "lifecycle:end" },
      ],
      authorizations: [],
      operation: null,
      bundle_fingerprint: "sha256:bundle",
      expires_at_unix_ms: 100,
    };
    expect(() => validateDialogRequest(request)).not.toThrow();
    expect(dialogGuardIds(request)).toEqual(["guard-a", "guard-b"]);
  });

  it("rejects empty or markup-bearing configured feedback and auditor findings", () => {
    const request = {
      schema: "arc.decision.dialog.request.v2" as const,
      request_id: "request-v2-findings",
      presentation_kind: "guard_failures" as const,
      title: "Guard failures",
      scope: "this activation",
      violations: [
        {
          guard_id: "guard-a",
          summary: "Configured feedback",
          configured_feedback: "  ",
          auditor_findings: "  ",
          scope: "lifecycle:end",
        },
      ],
      authorizations: [],
      operation: null,
      bundle_fingerprint: "sha256:bundle",
      expires_at_unix_ms: 100,
    };
    expect(() => validateDialogRequest(request)).toThrow(TypeError);

    request.violations[0].configured_feedback = "<script>blocked</script>";
    request.violations[0].auditor_findings = "Finding";
    expect(() => validateDialogRequest(request)).toThrow(TypeError);

    request.violations[0].configured_feedback = "x".repeat(16 * 1024 + 1);
    expect(() => validateDialogRequest(request)).toThrow(TypeError);

    request.violations[0].configured_feedback = "Feedback";
    request.violations[0].auditor_findings = "  ";
    expect(() => validateDialogRequest(request)).toThrow(TypeError);

    request.violations[0].auditor_findings = "<script>blocked</script>";
    expect(() => validateDialogRequest(request)).toThrow(TypeError);

    request.violations[0].auditor_findings = "x".repeat(16 * 1024 + 1);
    expect(() => validateDialogRequest(request)).toThrow(TypeError);
  });

  it("validates multiple exact authorizations and exposes all guard IDs", () => {
    const request = {
      schema: "arc.decision.dialog.request.v2" as const,
      request_id: "request-v2-multi",
      presentation_kind: "exact_operation_authorization" as const,
      title: "Authorize multiple guards",
      scope: "once",
      violations: [],
      authorizations: [
        {
          guard_id: "guard-1",
          summary: "Confirm first guard",
          auditor_findings: "The audit supports this exact operation.",
          operation_fingerprint: "sha256:operation",
        },
        {
          guard_id: "guard-2",
          summary: "Confirm second guard",
          operation_fingerprint: "sha256:operation",
        },
      ],
      operation: "git push",
      bundle_fingerprint: "sha256:bundle",
      expires_at_unix_ms: 100,
    };
    expect(() => validateDialogRequest(request)).not.toThrow();
    expect(dialogGuardIds(request)).toEqual(["guard-1", "guard-2"]);

    request.authorizations[0].auditor_findings = "<script>blocked</script>";
    expect(() => validateDialogRequest(request)).toThrow(TypeError);
  });

  it("rejects mixed aggregated violations and exact authorization", () => {
    const request = {
      schema: "arc.decision.dialog.request.v2" as const,
      request_id: "request-v2-mixed",
      presentation_kind: "exact_operation_authorization" as const,
      title: "Authorize",
      scope: "once",
      violations: [{ guard_id: "guard-a", summary: "blocked", scope: "tool" }],
      authorizations: [
        {
          guard_id: "guard-a",
          summary: "Authorize exact operation",
          operation_fingerprint: "sha256:operation",
        },
      ],
      operation: "git status",
      bundle_fingerprint: "sha256:bundle",
      expires_at_unix_ms: 100,
    };
    expect(() => validateDialogRequest(request)).toThrow(TypeError);
  });

  it("rejects exact authorization without an operation fingerprint", () => {
    const request = {
      schema: "arc.decision.dialog.request.v2" as const,
      request_id: "request-v2-unbound",
      presentation_kind: "exact_operation_authorization" as const,
      title: "Authorize",
      scope: "once",
      violations: [],
      authorizations: [
        {
          guard_id: "guard-a",
          summary: "Authorize exact operation",
          operation_fingerprint: "   ",
        },
      ],
      operation: "git status",
      bundle_fingerprint: "sha256:bundle",
      expires_at_unix_ms: 100,
    };
    expect(() => validateDialogRequest(request)).toThrow(TypeError);
  });

  it("validates aggregate decision with both violations and authorizations", () => {
    const request = {
      schema: "arc.decision.dialog.request.v2" as const,
      request_id: "request-v2-aggregate",
      presentation_kind: "aggregate_decision" as const,
      title: "Aggregate Policy Decision",
      scope: "activation",
      violations: [
        {
          guard_id: "guard-ask",
          summary: "Requires explicit operator confirmation",
          scope: "activation",
        },
      ],
      authorizations: [
        {
          guard_id: "guard-auth",
          summary: "Authorize command execution",
          operation_fingerprint: "sha256:operation",
        },
      ],
      operation: "git checkout",
      bundle_fingerprint: "sha256:bundle",
      expires_at_unix_ms: 100,
    };
    expect(() => validateDialogRequest(request)).not.toThrow();
  });

  it("rejects aggregate decision when both violations and authorizations are empty", () => {
    const request = {
      schema: "arc.decision.dialog.request.v2" as const,
      request_id: "request-v2-empty-agg",
      presentation_kind: "aggregate_decision" as const,
      title: "Empty Aggregate",
      scope: "activation",
      violations: [],
      authorizations: [],
      operation: null,
      bundle_fingerprint: "sha256:bundle",
      expires_at_unix_ms: 100,
    };
    expect(() => validateDialogRequest(request)).toThrow(TypeError);
  });

  it("rejects aggregate decision with authorizations but missing operation", () => {
    const request = {
      schema: "arc.decision.dialog.request.v2" as const,
      request_id: "request-v2-no-op",
      presentation_kind: "aggregate_decision" as const,
      title: "Missing Op",
      scope: "activation",
      violations: [],
      authorizations: [
        {
          guard_id: "guard-auth",
          summary: "Authorize command execution",
          operation_fingerprint: "sha256:operation",
        },
      ],
      operation: null,
      bundle_fingerprint: "sha256:bundle",
      expires_at_unix_ms: 100,
    };
    expect(() => validateDialogRequest(request)).toThrow(TypeError);
  });

  describe("REQ-001: failed_probes on a violation", () => {
    type Probe = { rule_name?: string | null; command: string; reason?: string | null };

    function requestWith(failedProbes: Probe[] | undefined, extra: Record<string, unknown> = {}) {
      const violation: Record<string, unknown> = {
        guard_id: "guard-a",
        summary: "Tests are missing",
        scope: "lifecycle:end",
        ...extra,
      };
      if (failedProbes !== undefined) violation.failed_probes = failedProbes;
      return {
        schema: "arc.decision.dialog.request.v2" as const,
        request_id: "request-probes",
        presentation_kind: "guard_failures" as const,
        title: "Guard failures",
        scope: "this activation",
        violations: [violation],
        authorizations: [],
        operation: null,
        bundle_fingerprint: "sha256:bundle",
        expires_at_unix_ms: 100,
      };
    }

    it("exports the per-guard limit of 64 and the matching DIALOG_LIMITS entry", () => {
      expect((DIALOG_LIMITS as Record<string, number>).failed_probes).toBe(64);
    });

    it("accepts rule plus command, an inline command alone, and a negated reason", () => {
      const probes: Probe[] = [
        { rule_name: "tests-green", command: "cargo test" },
        { command: "git status --porcelain" },
        { rule_name: null, command: "cat .wip", reason: "negated expression evaluated to true" },
      ];
      const request = requestWith(probes);
      expect(() => validateDialogRequest(request as never)).not.toThrow();
      const parsed = parseDialogRequest(request);
      expect(parsed.violations[0]).toHaveProperty("failed_probes", probes);
    });

    it("keeps a violation without failed_probes valid and without the key after parsing", () => {
      const parsed = parseDialogRequest(requestWith(undefined));
      expect("failed_probes" in parsed.violations[0]).toBe(false);
      expect(() => validateDialogRequest(parsed)).not.toThrow();
    });

    it("accepts exactly 64 entries and rejects 65", () => {
      const probes = (count: number): Probe[] =>
        Array.from({ length: count }, (_, index) => ({ command: `probe-${index}` }));
      expect(() => validateDialogRequest(requestWith(probes(64)) as never)).not.toThrow();
      expect(() => validateDialogRequest(requestWith(probes(65)) as never)).toThrow(TypeError);
      expect(() => parseDialogRequest(requestWith(probes(65)))).toThrow(TypeError);
    });

    it("rejects a blank command and counts the command limit in code points", () => {
      for (const command of ["", "   ", "\u0085"]) {
        expect(() => validateDialogRequest(requestWith([{ command }]) as never), command).toThrow(
          TypeError,
        );
      }
      const astral = "😀".repeat(256);
      expect(() => validateDialogRequest(requestWith([{ command: astral }]) as never)).not.toThrow();
      expect(() =>
        validateDialogRequest(requestWith([{ command: astral + "a" }]) as never),
      ).toThrow(TypeError);
    });

    it("shows shell text and angle brackets in a command or rule name without a markup check", () => {
      const probes: Probe[] = [
        { rule_name: "a<b>rule", command: "echo <script>x</script> 2>/dev/null" },
      ];
      expect(() => validateDialogRequest(requestWith(probes) as never)).not.toThrow();
    });

    it("checks the rule name and the reason like the Rust validator", () => {
      const check = (probe: Probe) => () =>
        validateDialogRequest(requestWith([probe]) as never);
      expect(check({ rule_name: "  ", command: "c" })).toThrow(TypeError);
      expect(check({ rule_name: "r".repeat(257), command: "c" })).toThrow(TypeError);
      expect(check({ rule_name: "r".repeat(256), command: "c" })).not.toThrow();
      expect(check({ command: "c", reason: "" })).toThrow(TypeError);
      expect(check({ command: "c", reason: "<b>bold</b>" })).toThrow(TypeError);
      expect(check({ command: "c", reason: "x".repeat(513) })).toThrow(TypeError);
      expect(check({ command: "c", reason: "x".repeat(512) })).not.toThrow();
      expect(check({ command: "c", reason: "a < b" })).not.toThrow();
    });

    it("rejects malformed entries when parsing", () => {
      // A well-formed list parses, so every rejection below is about its own defect.
      expect(() => parseDialogRequest(requestWith([{ command: "c" }]))).not.toThrow();
      for (const failedProbes of [
        null,
        "x",
        ["x"],
        [null],
        [{ rule_name: "r" }],
        [{ command: "c", extra: 1 }],
        [{ command: "c", expected_values: ["x"] }],
        [{ command: 7 }],
        [{ command: "c", rule_name: 3 }],
        [{ command: "c", reason: 3 }],
      ]) {
        const request = requestWith(undefined, { failed_probes: failedProbes });
        expect(() => parseDialogRequest(request), JSON.stringify(failedProbes)).toThrow(TypeError);
      }
    });
  });

  it("selects the Tauri bridge from the runtime marker", () => {
    const runtime = globalThis as typeof globalThis & { isTauri?: boolean };
    const previousMarker = runtime.isTauri;
    runtime.isTauri = true;

    try {
      expect(createDecisionBridge()).toBeInstanceOf(TauriDecisionBridge);
    } finally {
      if (previousMarker === undefined) {
        delete runtime.isTauri;
      } else {
        runtime.isTauri = previousMarker;
      }
    }
  });

  it("keeps the browser preview bridge outside the Tauri runtime", () => {
    const runtime = globalThis as typeof globalThis & { isTauri?: boolean };
    const previousMarker = runtime.isTauri;
    delete runtime.isTauri;

    try {
      expect(createDecisionBridge()).toBeInstanceOf(PreviewDecisionBridge);
    } finally {
      if (previousMarker !== undefined) {
        runtime.isTauri = previousMarker;
      }
    }
  });

  it("bounds user input by Unicode code point", () => {
    expect(boundUserMessage("a✅bcde", 4)).toBe("a✅bc");
  });

  it("normalizes only an empty optional message to null", () => {
    expect(optionalUserMessage("  ")).toBeNull();
    expect(optionalUserMessage("  approved once  ")).toBe("approved once");
  });

  it("classifies frontend errors into the bounded failure enum", () => {
    expect(classifyFrontendError(new Error("private details"))).toBe("invoke_rejected");
    expect(classifyFrontendError(new TypeError("private details"))).toBe("invalid_payload");
    expect(classifyFrontendError(null)).toBe("unknown");
  });

  it("keeps preview decisions local and preserves exact correlation", async () => {
    const bridge = new PreviewDecisionBridge(viewModel);
    const loaded = await bridge.load();
    loaded.request.title = "mutated copy";
    expect((await bridge.load()).request.title).toBe("Decision");

    await bridge.submit({
      request_id: "request-test",
      decision: "allow",
      message: "approved",
    });
    await bridge.dismiss("request-test");

    expect(bridge.submissions).toEqual([
      {
        request_id: "request-test",
        decision: "allow",
        message: "approved",
      },
    ]);
    expect(bridge.dismissals).toEqual(["request-test"]);
  });
});
