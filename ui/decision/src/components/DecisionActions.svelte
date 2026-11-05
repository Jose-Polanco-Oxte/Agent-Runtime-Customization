<script lang="ts">
  interface Props {
    disabled: boolean;
    onAllow: () => void;
    onDeny: () => void;
  }

  let { disabled, onAllow, onDeny }: Props = $props();
</script>

<footer class="action-bar" aria-label="Decision actions">
  <p>Choose only for the displayed scope.</p>
  <div class="action-buttons">
    <button class="button button-deny" type="button" {disabled} onclick={onDeny}>Deny</button>
    <button class="button button-allow" type="button" {disabled} onclick={onAllow}>Allow</button>
  </div>
</footer>
