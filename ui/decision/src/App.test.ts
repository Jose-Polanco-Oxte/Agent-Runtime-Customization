import { clearMocks, mockIPC, mockWindows } from "@tauri-apps/api/mocks";
import { render, screen, waitFor } from "@testing-library/svelte";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App.svelte";
import type {
  DecisionBridge,
  DecisionViewModel,
  FrontendFailure,
} from "./lib/contracts";
import { TauriDecisionBridge } from "./lib/tauri-bridge";

const viewModel: DecisionViewModel = {
  request: {
    schema: "arc.decision.dialog.request.v2",
    request_id: "request-app",
    presentation_kind: "guard_failures",
    title: "App bootstrap",
    scope: "once",
    violations: [
      {
        guard_id: "guard.app",
        summary: "Render the validated request.",
        scope: "once",
      },
    ],
    authorizations: [],
    operation: null,
    bundle_fingerprint: "sha256:preview-bundle-app",
    expires_at_unix_ms: 0,
  },
  theme: "dark",
  max_user_message_chars: 20,
  preview: false,
};

function bridgeWith(overrides: Partial<DecisionBridge> = {}): DecisionBridge {
  return {
    load: vi.fn(async () => viewModel),
    ready: vi.fn(async () => undefined),
    failed: vi.fn(async (_failure: FrontendFailure) => undefined),
    submit: vi.fn(async () => undefined),
    dismiss: vi.fn(async () => undefined),
    ...overrides,
  };
}

afterEach(() => {
  clearMocks();
  vi.unstubAllGlobals();
  delete document.documentElement.dataset.arcReadiness;
});

describe("App bootstrap", () => {
  it("waits for the DOM to settle before reporting ready", async () => {
    const events: string[] = [];
    const bridge = bridgeWith({
      ready: vi.fn(async () => {
        const dom = document.querySelector(".dialog-shell") ? "dom-settled" : "too-early";
        events.push(`${dom}:${document.documentElement.dataset.arcReadiness}`);
      }),
    });

    render(App, { props: { bridge } });
    await waitFor(() => expect(events).toEqual(["dom-settled:dom-settled"]));
    expect(document.documentElement.dataset.arcReadiness).toBe("ready");
  });

  it("keeps decision actions disabled until the host accepts frontend readiness", async () => {
    let resolveReady: (() => void) | undefined;
    const bridge = bridgeWith({
      ready: vi.fn(
        () =>
          new Promise<void>((resolve) => {
            resolveReady = resolve;
          }),
      ),
    });

    render(App, { props: { bridge } });
    const allow = await screen.findByRole("button", { name: "Allow" });
    const deny = screen.getByRole("button", { name: "Deny" });
    expect(allow).toBeDisabled();
    expect(deny).toBeDisabled();

    resolveReady?.();
    await waitFor(() => {
      expect(allow).toBeEnabled();
      expect(deny).toBeEnabled();
    });
  });

  it("reports a sanitized load failure without exposing the thrown error", async () => {
    const failure = new Error("secret request and stack details");
    const bridge = bridgeWith({
      load: vi.fn(async () => {
        throw failure;
      }),
    });

    render(App, { props: { bridge } });
    await waitFor(() => expect(bridge.failed).toHaveBeenCalledOnce());
    expect(bridge.failed).toHaveBeenCalledWith({
      request_id: null,
      stage: "load_request",
      code: "invoke_rejected",
    });
    expect(document.documentElement.dataset.arcReadiness).toBe("failed");
    expect(screen.getByRole("alert")).not.toHaveTextContent("secret");
  });

  it("reports a ready rejection with the loaded request correlation", async () => {
    const bridge = bridgeWith({
      ready: vi.fn(async () => {
        throw new Error("ready failed");
      }),
    });

    render(App, { props: { bridge } });
    await waitFor(() => expect(bridge.failed).toHaveBeenCalledOnce());
    expect(bridge.failed).toHaveBeenCalledWith({
      request_id: "request-app",
      stage: "render_or_ready",
      code: "invoke_rejected",
    });
    expect(document.documentElement.dataset.arcReadiness).toBe("failed");
  });

  it("does not retry when frontend_failed itself rejects", async () => {
    const bridge = bridgeWith({
      load: vi.fn(async () => {
        throw new Error("load failed");
      }),
      failed: vi.fn(async () => {
        throw new Error("IPC unavailable");
      }),
    });

    render(App, { props: { bridge } });
    await waitFor(() => expect(screen.getByRole("alert")).toBeVisible());
    expect(bridge.failed).toHaveBeenCalledOnce();
  });

  it("updates the rendered theme when the system preference changes", async () => {
    let isDark = false;
    let changeListener: (() => void) | undefined;
    const mediaQuery = {
      get matches() {
        return isDark;
      },
      addEventListener: (_type: string, listener: () => void) => {
        changeListener = listener;
      },
      removeEventListener: () => undefined,
    } as unknown as MediaQueryList;
    vi.stubGlobal("matchMedia", vi.fn(() => mediaQuery));

    render(App, { props: { bridge: bridgeWith() } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Allow" })).toBeEnabled());
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(document.querySelector(".dialog-shell")).toHaveAttribute("data-theme", "light");

    isDark = true;
    changeListener?.();
    await waitFor(() => {
      expect(document.documentElement.dataset.theme).toBe("dark");
      expect(document.querySelector(".dialog-shell")).toHaveAttribute("data-theme", "dark");
    });
  });
});

describe("App bootstrap through Tauri mockIPC", () => {
  it("uses the real bridge command names and payloads after DOM settlement", async () => {
    mockWindows("decision");
    const invocations: Array<{ command: string; payload: unknown }> = [];
    mockIPC((command, payload) => {
      invocations.push({ command, payload });
      if (command === "get_decision_request") return viewModel;
      if (command === "frontend_ready") return undefined;
      if (command === "submit_decision") return undefined;
      throw new Error(`unexpected command: ${command}`);
    });

    render(App, { props: { bridge: new TauriDecisionBridge() } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Allow" })).toBeEnabled());

    expect(invocations.slice(0, 2)).toEqual([
      { command: "get_decision_request", payload: {} },
      { command: "frontend_ready", payload: { requestId: "request-app" } },
    ]);
  });

  it("maps a real bridge load rejection to one sanitized frontend_failed invoke", async () => {
    mockWindows("decision");
    const invocations: Array<{ command: string; payload: unknown }> = [];
    mockIPC((command, payload) => {
      invocations.push({ command, payload });
      if (command === "get_decision_request") {
        throw new Error("secret request details");
      }
      if (command === "frontend_failed") return undefined;
      throw new Error(`unexpected command: ${command}`);
    });

    render(App, { props: { bridge: new TauriDecisionBridge() } });
    await waitFor(() => expect(screen.getByRole("alert")).toBeVisible());

    expect(invocations).toEqual([
      { command: "get_decision_request", payload: {} },
      {
        command: "frontend_failed",
        payload: {
          failure: {
            request_id: null,
            stage: "load_request",
            code: "invoke_rejected",
          },
        },
      },
    ]);
    expect(screen.getByRole("alert")).not.toHaveTextContent("secret");
  });

  it("reports a real bridge ready rejection without retrying readiness", async () => {
    mockWindows("decision");
    const invocations: Array<{ command: string; payload: unknown }> = [];
    mockIPC((command, payload) => {
      invocations.push({ command, payload });
      if (command === "get_decision_request") return viewModel;
      if (command === "frontend_ready") throw new Error("ready unavailable");
      if (command === "frontend_failed") return undefined;
      throw new Error(`unexpected command: ${command}`);
    });

    render(App, { props: { bridge: new TauriDecisionBridge() } });
    await waitFor(() => expect(screen.getByRole("alert")).toBeVisible());

    expect(invocations).toEqual([
      { command: "get_decision_request", payload: {} },
      { command: "frontend_ready", payload: { requestId: "request-app" } },
      {
        command: "frontend_failed",
        payload: {
          failure: {
            request_id: "request-app",
            stage: "render_or_ready",
            code: "invoke_rejected",
          },
        },
      },
    ]);
  });
});

// REQ-010 (AC-010.3, AC-010.5): the invoke result crosses the IPC boundary unchecked by the
// type system, so the TS side must validate it before rendering anything.
const malformedInvokeResults: Array<[string, unknown]> = [
  [
    "unknown presentation kind",
    { ...viewModel, request: { ...viewModel.request, presentation_kind: "bulk_decision" } },
  ],
  ["title over the Rust limit", { ...viewModel, request: { ...viewModel.request, title: "t".repeat(257) } }],
  ["blank title made of U+0085", { ...viewModel, request: { ...viewModel.request, title: "\u0085" } }],
  ["unknown view model key", { ...viewModel, locale: "es" }],
  ["unknown theme", { ...viewModel, theme: "purple" }],
  ["max_user_message_chars above the host bound", { ...viewModel, max_user_message_chars: 4001 }],
  ["preview that is not a boolean", { ...viewModel, preview: "false" }],
  ["request key absent", { theme: "dark", max_user_message_chars: 20, preview: false }],
  ["null result", null],
  ["string result", "not a view model"],
];

describe("App bootstrap rejects malformed invoke results", () => {
  it.each(malformedInvokeResults)(
    "renders no dialog and sends one invalid_payload frontend_failed for: %s",
    async (_label, malformed) => {
      mockWindows("decision");
      const invocations: Array<{ command: string; payload: unknown }> = [];
      mockIPC((command, payload) => {
        invocations.push({ command, payload });
        if (command === "get_decision_request") return malformed;
        if (command === "frontend_failed") return undefined;
        throw new Error(`unexpected command: ${command}`);
      });

      render(App, { props: { bridge: new TauriDecisionBridge() } });
      await waitFor(() => expect(screen.getByRole("alert")).toBeVisible());

      expect(invocations).toEqual([
        { command: "get_decision_request", payload: {} },
        {
          command: "frontend_failed",
          payload: {
            failure: { request_id: null, stage: "load_request", code: "invalid_payload" },
          },
        },
      ]);
      expect(document.querySelector(".dialog-shell")).toBeNull();
      expect(screen.queryByRole("button", { name: "Allow" })).toBeNull();
      expect(document.documentElement.dataset.arcReadiness).toBe("failed");
    },
  );

  it.each(malformedInvokeResults)(
    "TauriDecisionBridge.load rejects with a TypeError for: %s",
    async (_label, malformed) => {
      mockWindows("decision");
      mockIPC((command) => {
        if (command === "get_decision_request") return malformed;
        throw new Error(`unexpected command: ${command}`);
      });

      await expect(new TauriDecisionBridge().load()).rejects.toBeInstanceOf(TypeError);
    },
  );

  it("TauriDecisionBridge.load still resolves a valid view model unchanged", async () => {
    mockWindows("decision");
    mockIPC((command) => {
      if (command === "get_decision_request") return viewModel;
      throw new Error(`unexpected command: ${command}`);
    });

    await expect(new TauriDecisionBridge().load()).resolves.toEqual(viewModel);
  });
});
