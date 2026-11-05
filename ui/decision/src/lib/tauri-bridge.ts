import { invoke } from "@tauri-apps/api/core";
import type {
  DecisionBridge,
  DecisionSubmission,
  DecisionViewModel,
  FrontendFailure,
} from "./contracts";
import { parseDecisionViewModel } from "./contracts";

export class TauriDecisionBridge implements DecisionBridge {
  async load(): Promise<DecisionViewModel> {
    return parseDecisionViewModel(await invoke<unknown>("get_decision_request"));
  }

  ready(requestId: string): Promise<void> {
    return invoke("frontend_ready", { requestId });
  }

  failed(failure: FrontendFailure): Promise<void> {
    return invoke("frontend_failed", { failure });
  }

  submit(submission: DecisionSubmission): Promise<void> {
    return invoke("submit_decision", { submission });
  }

  dismiss(requestId: string): Promise<void> {
    return invoke("dismiss_decision", { requestId });
  }
}
