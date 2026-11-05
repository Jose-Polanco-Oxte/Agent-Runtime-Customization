<script lang="ts">
  import type { DecisionIntent, DecisionViewModel } from "../lib/contracts";
  import { boundUserMessage } from "../lib/contracts";
  import DecisionActions from "./DecisionActions.svelte";
  import RequestContext from "./RequestContext.svelte";

  interface Props {
    viewModel: DecisionViewModel;
    disabled: boolean;
    onSubmit: (decision: DecisionIntent, message: string) => void;
    onDismiss: () => void;
  }

  let { viewModel, disabled, onSubmit, onDismiss }: Props = $props();
  let userMessage = $state("");
  let characterCount = $derived(Array.from(userMessage).length);

  function updateMessage(event: Event): void {
    const target = event.currentTarget as HTMLTextAreaElement;
    userMessage = boundUserMessage(target.value, viewModel.max_user_message_chars);
  }

  function handleKeydown(event: KeyboardEvent): void {
    if (event.key === "Escape" && !disabled) {
      event.preventDefault();
      onDismiss();
    }
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<main class="dialog-shell" data-theme={viewModel.theme}>
  <div class="dialog-content">
    <header class="dialog-header">
      <span class="eyebrow">Arc guard</span>
      <h1>{viewModel.request.title}</h1>
    </header>

    {#if viewModel.preview}
      <p class="preview-banner">Design preview — no runtime decision will be recorded.</p>
    {/if}

    <RequestContext request={viewModel.request} />

    <section class="message-field">
      <div class="field-heading">
        <label id="optional-message-label" for="decision-message">Optional message to the agent</label>
        <span>{characterCount} / {viewModel.max_user_message_chars}</span>
      </div>
      <textarea
        id="decision-message"
        rows="4"
        value={userMessage}
        disabled={disabled}
        oninput={updateMessage}
        placeholder="Add context for this decision"
      ></textarea>
    </section>
  </div>

  <DecisionActions
    {disabled}
    onAllow={() => onSubmit("allow", userMessage)}
    onDeny={() => onSubmit("deny", userMessage)}
  />
</main>
