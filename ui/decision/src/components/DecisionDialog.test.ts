import { fireEvent, render, screen } from "@testing-library/svelte";
import { describe, expect, it, vi } from "vitest";
import type { DecisionIntent, DecisionViewModel } from "../lib/contracts";
import DecisionDialog from "./DecisionDialog.svelte";

const viewModel: DecisionViewModel = {
  request: {
    schema: "arc.decision.dialog.request.v2",
    request_id: "request-component",
    presentation_kind: "exact_operation_authorization",
    title: "Review <literal> operation",
    scope: "exact operation once",
    violations: [],
    authorizations: [
      {
        guard_id: "guard.component",
        summary: "Do not interpret <script>text</script> as markup ✅",
        operation_fingerprint: "op-1",
      },
    ],
    operation: "Bash git status",
    bundle_fingerprint: "sha256:preview-bundle-comp",
    expires_at_unix_ms: 0,
  },
  theme: "dark",
  max_user_message_chars: 4,
  preview: false,
};

describe("DecisionDialog", () => {
  it("renders request content as literal text with both explicit actions", () => {
    render(DecisionDialog, {
      viewModel,
      disabled: false,
      onSubmit: vi.fn(),
      onDismiss: vi.fn(),
    });

    expect(screen.getByRole("heading", { name: "Review <literal> operation" })).toBeVisible();
    expect(screen.getByText("Do not interpret <script>text</script> as markup ✅")).toBeVisible();
    expect(document.querySelector("script")).toBeNull();
    expect(screen.getByRole("button", { name: "Deny" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Allow" })).toBeEnabled();
  });

  it("bounds Unicode input and sends one exact Allow intent", async () => {
    const submissions: Array<[DecisionIntent, string]> = [];
    render(DecisionDialog, {
      viewModel,
      disabled: false,
      onSubmit: (decision, message) => submissions.push([decision, message]),
      onDismiss: vi.fn(),
    });

    const message = screen.getByLabelText("Optional message to the agent");
    await fireEvent.input(message, { target: { value: "a✅bcde" } });
    expect(message).toHaveValue("a✅bc");
    expect(screen.getByText("4 / 4")).toBeVisible();

    await fireEvent.click(screen.getByRole("button", { name: "Allow" }));
    expect(submissions).toEqual([["allow", "a✅bc"]]);
  });

  it("keeps Deny explicit and maps Escape only to dismiss", async () => {
    const onSubmit = vi.fn();
    const onDismiss = vi.fn();
    render(DecisionDialog, {
      viewModel,
      disabled: false,
      onSubmit,
      onDismiss,
    });

    await fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    expect(onSubmit).toHaveBeenCalledExactlyOnceWith("deny", "");
    expect(onDismiss).not.toHaveBeenCalled();

    await fireEvent.keyDown(window, { key: "Escape" });
    expect(onDismiss).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });

  it("suppresses every authorizing or dismissing action while disabled", async () => {
    const onSubmit = vi.fn();
    const onDismiss = vi.fn();
    render(DecisionDialog, {
      viewModel,
      disabled: true,
      onSubmit,
      onDismiss,
    });

    expect(screen.getByLabelText("Optional message to the agent")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Deny" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Allow" })).toBeDisabled();
    await fireEvent.keyDown(window, { key: "Escape" });
    expect(onSubmit).not.toHaveBeenCalled();
    expect(onDismiss).not.toHaveBeenCalled();
  });
});
