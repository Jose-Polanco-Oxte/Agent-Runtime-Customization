<script lang="ts">
  import type { DialogRequest } from "../lib/contracts";
  import { dialogGuardIds, dialogOperation } from "../lib/contracts";

  interface Props {
    request: DialogRequest;
  }

  let { request }: Props = $props();
</script>

<section class="context-card" aria-labelledby="decision-context-title">
  <h2 id="decision-context-title">Decision context</h2>
  {#if request.violations.length > 0}
    <ul aria-label="Failed guards">
      {#each request.violations as violation (violation.guard_id)}
        <li>
          <code>{violation.guard_id}</code>: <span class="context-summary">{violation.summary}</span>
          {#if violation.configured_feedback}
            <p class="violation-explanation"><strong>Configured feedback</strong><span class="context-summary">{violation.configured_feedback}</span></p>
          {/if}
          {#if violation.auditor_findings}
            <p class="violation-explanation"><strong>Auditor findings</strong><span class="context-summary">{violation.auditor_findings}</span></p>
          {/if}
          {#if violation.failed_probes && violation.failed_probes.length > 0}
            <div class="violation-explanation failed-probes">
              <strong>Failed probes</strong>
              <ul aria-label="Failed probes">
                {#each violation.failed_probes as probe}
                  <li>
                    {#if probe.rule_name}<span class="probe-rule">{probe.rule_name}</span>{/if}
                    <code>{probe.command}</code>
                    {#if probe.reason}<span class="probe-reason">{probe.reason}</span>{/if}
                  </li>
                {/each}
              </ul>
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
  {#if request.authorizations.length > 0}
    <ul aria-label="Required authorizations">
      {#each request.authorizations as auth (auth.guard_id)}
        <li>
          <code>{auth.guard_id}</code>: <span class="context-summary">{auth.summary}</span>
          {#if auth.auditor_findings}
            <p class="violation-explanation"><strong>Auditor findings</strong><span class="context-summary">{auth.auditor_findings}</span></p>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</section>

<section class="details-card" aria-labelledby="request-details-title">
  <h2 id="request-details-title">Request details</h2>
  <dl>
    {#if dialogGuardIds(request).length > 0}
      <div>
        <dt>Guard</dt>
        <dd><code>{dialogGuardIds(request).join(", ")}</code></dd>
      </div>
    {/if}
    {#if dialogOperation(request)}
      <div>
        <dt>Operation</dt>
        <dd><code>{dialogOperation(request)}</code></dd>
      </div>
    {/if}
    <div>
      <dt>Scope</dt>
      <dd>{request.scope}</dd>
    </div>
  </dl>
</section>
