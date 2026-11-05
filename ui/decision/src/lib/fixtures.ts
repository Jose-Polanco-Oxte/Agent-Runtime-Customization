import type { DecisionViewModel } from "./contracts";

const base: DecisionViewModel = {
  request: {
    schema: "arc.decision.dialog.request.v2",
    request_id: "preview-decision-1",
    presentation_kind: "guard_failures",
    title: "Arc policy decision",
    scope: "this exact pending operation once",
    violations: [
      {
        guard_id: "clean_completion",
        summary: "The agent wants to execute an operation protected by an Arc guard.",
        scope: "lifecycle:end",
      },
    ],
    authorizations: [],
    operation: "lifecycle:end",
    bundle_fingerprint: "sha256:preview-bundle-1",
    expires_at_unix_ms: 0,
  },
  theme: "dark",
  max_user_message_chars: 4_000,
  preview: true,
};

const fixtures: Record<string, DecisionViewModel> = {
  default: base,
  minimal: {
    ...base,
    request: {
      ...base.request,
      request_id: "preview-minimal",
      violations: [
        {
          guard_id: "policy_check",
          summary: "Allow this operation?",
          scope: "once",
        },
      ],
      operation: null,
      scope: "once",
    },
  },
  long: {
    ...base,
    request: {
      ...base.request,
      request_id: "preview-long",
      title: "Review a long policy context",
      violations: Array.from({ length: 18 }, (_, index) => ({
        guard_id: `guard_${index + 1}`,
        summary: `Finding ${index + 1}: the protected operation must preserve correlation and fail closed.`,
        scope: "shell: cargo test --workspace --all-targets",
      })),
      operation: "shell: cargo test --workspace --all-targets",
    },
  },
  unicode: {
    ...base,
    request: {
      ...base.request,
      request_id: "preview-unicode",
      title: "Unicode decision ✅",
      violations: [
        {
          guard_id: "unicode_guard",
          summary: "Literal text is not markup: مرحبا بالعالم - 日本語の説明",
          scope: 'tool_call: "deploy 🚀"',
        },
      ],
      operation: 'tool_call: "deploy 🚀"',
    },
  },
  light: {
    ...base,
    theme: "light",
    request: { ...base.request, request_id: "preview-light" },
  },
};

export function fixtureFromLocation(location: Pick<Location, "search">): DecisionViewModel {
  const query = new URLSearchParams(location.search);
  const fixture = fixtures[query.get("fixture") ?? "default"] ?? fixtures.default;
  const theme = query.get("theme");
  return {
    ...fixture,
    theme: theme === "light" || theme === "dark" ? theme : fixture.theme,
    request: { ...fixture.request },
  };
}
