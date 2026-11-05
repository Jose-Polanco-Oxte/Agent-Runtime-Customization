import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { browser } from "@wdio/globals";

const AUTHORIZED_WINDOW_LABEL = "decision";
const UNAUTHORIZED_WINDOW_LABEL = "unauthorized";
const FIXTURE_REQUEST_ID = "webdriver-request";

type InvokeOutcome = "resolved" | "rejected" | "ipc_unavailable";

interface InvokeResult {
  outcome: InvokeOutcome;
}

interface EvidenceEvent {
  name: string;
  command?: string;
  result?: "PASS" | "FAIL";
}

interface WindowHandles {
  authorized: string;
  unauthorized: string;
}

function outputDirectory(): string {
  const value = process.env.ARC_WEBDRIVER_OUTPUT_DIR;
  if (!value) {
    throw new Error("ARC_WEBDRIVER_OUTPUT_DIR is required");
  }
  return path.resolve(value);
}

function writeAssertions(
  result: "PASS" | "FAIL",
  events: EvidenceEvent[],
  aclCommands: Array<{ command: string; result: "ACL_DENIED" }>,
  terminalAttemptsBeforeCleanup: number,
  structuredResponse?: unknown,
): void {
  const evidence = {
    schema_version: 1,
    result,
    readiness: {
      dom_rendered: events.some((event) => event.name === "authorized_dom_rendered"),
      backend_accepted: events.some((event) => event.name === "frontend_ready_accepted"),
    },
    acl: {
      authorized_window: "decision",
      unauthorized_window: "unauthorized",
      commands: aclCommands,
    },
    terminal: {
      attempts_before_driver_cleanup: terminalAttemptsBeforeCleanup,
    },
    roundtrip_response: structuredResponse ?? null,
    provider_layer: {
      status: "NOT-APPLICABLE",
      reason: "This isolated sidecar test has no provider event store, receipt, or waiver consumer.",
    },
    events,
  };
  fs.writeFileSync(
    path.join(outputDirectory(), "webdriver.json"),
    `${JSON.stringify(evidence, null, 2)}\n`,
    "utf8",
  );
}

async function locateFixtureWindows(): Promise<WindowHandles> {
  await browser.waitUntil(
    async () => (await browser.getWindowHandles()).length === 2,
    {
      timeout: 20_000,
      interval: 100,
      timeoutMsg: "expected exactly two Tauri WebView windows",
    },
  );

  let authorized: string | undefined;
  let unauthorized: string | undefined;
  for (const handle of await browser.getWindowHandles()) {
    await browser.switchToWindow(handle);
    const label = await browser.execute(() => {
      const tauriWindow = window as Window & {
        __TAURI_INTERNALS__?: {
          metadata?: {
            currentWindow?: {
              label?: string;
            };
          };
        };
      };
      return tauriWindow.__TAURI_INTERNALS__?.metadata?.currentWindow?.label ?? null;
    });
    if (label === AUTHORIZED_WINDOW_LABEL) {
      authorized = handle;
    } else if (label === UNAUTHORIZED_WINDOW_LABEL) {
      unauthorized = handle;
    }
  }

  assert.ok(authorized, "authorized decision window was not found");
  assert.ok(unauthorized, "unauthorized fixture window was not found");
  return { authorized, unauthorized };
}

async function invokeFromCurrentWindow(command: string, payload: unknown): Promise<InvokeResult> {
  return browser.executeAsync(
    (
      commandName: string,
      commandPayload: unknown,
      done: (result: InvokeResult) => void,
    ) => {
      const tauriWindow = window as Window & {
        __TAURI_INTERNALS__?: {
          invoke?: (name: string, args: unknown) => Promise<unknown>;
        };
      };
      const invoke = tauriWindow.__TAURI_INTERNALS__?.invoke;
      if (typeof invoke !== "function") {
        done({ outcome: "ipc_unavailable" });
        return;
      }
      void invoke(commandName, commandPayload).then(
        () => done({ outcome: "resolved" }),
        () => done({ outcome: "rejected" }),
      );
    },
    command,
    payload,
  );
}

function terminalAttemptsBeforeCleanup(): number {
  const evidencePath = path.join(outputDirectory(), "terminal-attempts.log");
  const contents = fs.readFileSync(evidencePath, "utf8");
  return contents.split(/\r?\n/u).filter((line) => line.length > 0).length;
}

describe("Arc decision UI WebDriver readiness and ACL", () => {
  it("accepts readiness only from decision and denies every command from unauthorized", async () => {
    const events: EvidenceEvent[] = [];
    const aclCommands: Array<{ command: string; result: "ACL_DENIED" }> = [];
    let observedTerminalAttempts = -1;

    try {
      const windows = await locateFixtureWindows();
      events.push({ name: "fixture_windows_located" });

      await browser.switchToWindow(windows.authorized);
      await browser.waitUntil(
        async () =>
          (await browser.execute(() => document.documentElement.dataset.arcReadiness)) === "ready",
        {
          timeout: 20_000,
          interval: 100,
          timeoutMsg: "authorized frontend did not expose accepted readiness",
        },
      );
      await browser.$(".dialog-shell").waitForExist();
      events.push({ name: "authorized_dom_rendered", result: "PASS" });
      events.push({ name: "frontend_ready_accepted", result: "PASS" });

      await browser.switchToWindow(windows.unauthorized);
      await browser.waitUntil(
        async () =>
          (await browser.execute(() => document.documentElement.dataset.arcReadiness)) === "failed",
        {
          timeout: 20_000,
          interval: 100,
          timeoutMsg: "unauthorized frontend did not expose its rejected bootstrap",
        },
      );
      await browser.$('[role="alert"]').waitForExist();
      assert.equal(await browser.$(".dialog-shell").isExisting(), false);
      events.push({ name: "unauthorized_bootstrap_rejected", result: "PASS" });

      const invocations: ReadonlyArray<{ command: string; payload: unknown }> = [
        { command: "get_decision_request", payload: {} },
        { command: "frontend_ready", payload: { requestId: FIXTURE_REQUEST_ID } },
        {
          command: "frontend_failed",
          payload: {
            failure: {
              request_id: FIXTURE_REQUEST_ID,
              stage: "render_or_ready",
              code: "invoke_rejected",
            },
          },
        },
        {
          command: "submit_decision",
          payload: {
            submission: {
              request_id: FIXTURE_REQUEST_ID,
              decision: "allow",
              message: null,
            },
          },
        },
        { command: "dismiss_decision", payload: { requestId: FIXTURE_REQUEST_ID } },
      ];

      for (const invocation of invocations) {
        const result = await invokeFromCurrentWindow(invocation.command, invocation.payload);
        assert.equal(
          result.outcome,
          "rejected",
          `${invocation.command} was not rejected for the unauthorized window`,
        );
        aclCommands.push({ command: invocation.command, result: "ACL_DENIED" });
        events.push({ name: "acl_denied", command: invocation.command, result: "PASS" });
      }

      observedTerminalAttempts = terminalAttemptsBeforeCleanup();
      assert.equal(
        observedTerminalAttempts,
        0,
        "an unauthorized invoke attempted to emit a terminal response",
      );
      events.push({ name: "no_terminal_response_from_unauthorized", result: "PASS" });

      await browser.switchToWindow(windows.authorized);
      const authorizedReady = await invokeFromCurrentWindow("frontend_ready", {
        requestId: FIXTURE_REQUEST_ID,
      });
      assert.equal(authorizedReady.outcome, "resolved");
      events.push({ name: "authorized_command_still_available", result: "PASS" });

      const failedGuardsList = await browser.$('ul[aria-label="Failed guards"]');
      await failedGuardsList.waitForExist({ timeout: 10_000 });
      const failedGuardsText = await failedGuardsList.getText();
      assert.ok(
        failedGuardsText.includes("webdriver-ask"),
        `expected webdriver-ask in failed guards list, found: ${failedGuardsText}`,
      );
      events.push({ name: "failed_guards_displayed", result: "PASS" });

      const requiredAuthList = await browser.$('ul[aria-label="Required authorizations"]');
      await requiredAuthList.waitForExist({ timeout: 10_000 });
      const requiredAuthText = await requiredAuthList.getText();
      assert.ok(
        requiredAuthText.includes("webdriver-auth"),
        `expected webdriver-auth in required authorizations list, found: ${requiredAuthText}`,
      );
      events.push({ name: "required_authorizations_displayed", result: "PASS" });

      const bodyText = await browser.$("body").getText();
      assert.ok(
        bodyText.includes("Bash git push"),
        `expected operation Bash git push visible in authorized window, found: ${bodyText}`,
      );
      events.push({ name: "operation_text_displayed", result: "PASS" });

      const allowButton = await browser.$("button.button-allow");
      await allowButton.waitForClickable({ timeout: 10_000 });
      await allowButton.click();
      events.push({ name: "allow_clicked", result: "PASS" });

      const responsePath = path.join(outputDirectory(), "structured-response.json");
      await browser.waitUntil(
        () => fs.existsSync(responsePath),
        {
          timeout: 10_000,
          interval: 100,
          timeoutMsg: "expected structured-response.json to be written by terminal response sink",
        },
      );
      const rawResponse = fs.readFileSync(responsePath, "utf8");
      const structuredResponse = JSON.parse(rawResponse);
      assert.equal(structuredResponse.request_id, FIXTURE_REQUEST_ID);
      assert.equal(
        structuredResponse.bundle_fingerprint,
        "sha256:semantic-bundle-fingerprint-12345678",
      );
      const decisionStatus =
        typeof structuredResponse.decision === "string"
          ? structuredResponse.decision
          : structuredResponse.decision?.status;
      assert.equal(decisionStatus, "allow");
      events.push({ name: "structured_response_verified", result: "PASS" });

      writeAssertions("PASS", events, aclCommands, observedTerminalAttempts, structuredResponse);
    } catch (error: unknown) {
      events.push({ name: "webdriver_assertion_failed", result: "FAIL" });
      writeAssertions("FAIL", events, aclCommands, observedTerminalAttempts);
      throw error;
    }
  });
});
