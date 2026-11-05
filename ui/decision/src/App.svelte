<script lang="ts">
  import { onMount, tick } from "svelte";
  import DecisionDialog from "./components/DecisionDialog.svelte";
  import type {
    DecisionBridge,
    DecisionIntent,
    DecisionViewModel,
    FrontendFailure,
    FrontendFailureStage,
    UiTheme,
  } from "./lib/contracts";
  import {
    classifyFrontendError,
    optionalUserMessage,
    parseDecisionViewModel,
  } from "./lib/contracts";

  interface Props {
    bridge: DecisionBridge;
  }

  let { bridge }: Props = $props();
  let viewModel = $state<DecisionViewModel | null>(null);
  let errorMessage = $state<string | null>(null);
  let submitting = $state(false);
  let frontendReady = $state(false);
  let previewOutcome = $state<string | null>(null);
  let systemTheme = $state<UiTheme | null>(null);

  onMount(() => {
    const unsubscribeFromSystemTheme = subscribeToSystemTheme();
    setReadiness("loading");
    void bootstrap();
    return unsubscribeFromSystemTheme;
  });

  function setReadiness(state: "loading" | "dom-settled" | "ready" | "failed"): void {
    document.documentElement.dataset.arcReadiness = state;
  }

  async function bootstrap(): Promise<void> {
    try {
      const loaded = await bridge.load();
      const parsed = parseDecisionViewModel(loaded);
      viewModel = parsed;
      applyTheme(systemTheme ?? viewModel.theme);
      await tick();
      setReadiness("dom-settled");
      await bridge.ready(viewModel.request.request_id);
      frontendReady = true;
      setReadiness("ready");
    } catch (error: unknown) {
      const stage: FrontendFailureStage = viewModel ? "render_or_ready" : "load_request";
      const failure: FrontendFailure = {
        request_id: viewModel?.request.request_id ?? null,
        stage,
        code: classifyFrontendError(error),
      };
      errorMessage = "The decision UI could not load a validated request.";
      setReadiness("failed");
      try {
        await bridge.failed(failure);
      } catch (_notificationError: unknown) {
        // The host may already be gone; never retry the failure notification.
      }
    }
  }

  function subscribeToSystemTheme(): () => void {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return () => undefined;
    }

    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    const updateTheme = (): void => {
      systemTheme = mediaQuery.matches ? "dark" : "light";
      applyTheme(systemTheme);
    };

    updateTheme();
    if (typeof mediaQuery.addEventListener === "function") {
      mediaQuery.addEventListener("change", updateTheme);
      return () => mediaQuery.removeEventListener("change", updateTheme);
    }

    mediaQuery.addListener(updateTheme);
    return () => mediaQuery.removeListener(updateTheme);
  }

  function applyTheme(theme: UiTheme): void {
    document.documentElement.dataset.theme = theme;
    if (viewModel && viewModel.theme !== theme) {
      viewModel = { ...viewModel, theme };
    }
  }

  async function submit(decision: DecisionIntent, message: string): Promise<void> {
    if (!viewModel || submitting) return;
    submitting = true;
    try {
      await bridge.submit({
        request_id: viewModel.request.request_id,
        decision,
        message: optionalUserMessage(message),
      });
      if (viewModel.preview) {
        previewOutcome = `Preview captured: ${decision}`;
        submitting = false;
      }
    } catch (error: unknown) {
      classifyFrontendError(error);
      errorMessage = "The decision could not be submitted. The operation remains unresolved.";
    }
  }

  async function dismiss(): Promise<void> {
    if (!viewModel || submitting) return;
    submitting = true;
    try {
      await bridge.dismiss(viewModel.request.request_id);
      if (viewModel.preview) {
        previewOutcome = "Preview captured: closed";
        submitting = false;
      }
    } catch (error: unknown) {
      classifyFrontendError(error);
      errorMessage = "The dialog could not close cleanly. The operation remains unresolved.";
    }
  }
</script>

{#if errorMessage}
  <main class="status-screen status-error" role="alert">
    <h1>Decision unavailable</h1>
    <p>{errorMessage}</p>
  </main>
{:else if viewModel}
  <DecisionDialog
    {viewModel}
    disabled={submitting || !frontendReady}
    onSubmit={submit}
    onDismiss={dismiss}
  />
  {#if previewOutcome}
    <div class="preview-outcome" role="status">{previewOutcome}</div>
  {/if}
{:else}
  <main class="status-screen" aria-busy="true">
    <div class="loading-mark" aria-hidden="true"></div>
    <p>Loading decision context…</p>
  </main>
{/if}
