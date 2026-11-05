import type {
  DecisionBridge,
  DecisionSubmission,
  DecisionViewModel,
  FrontendFailure,
} from "./contracts";
import { fixtureFromLocation } from "./fixtures";

export class PreviewDecisionBridge implements DecisionBridge {
  readonly submissions: DecisionSubmission[] = [];
  readonly dismissals: string[] = [];
  readonly failures: FrontendFailure[] = [];

  constructor(private readonly viewModel: DecisionViewModel) {}

  load(): Promise<DecisionViewModel> {
    return Promise.resolve(structuredClone(this.viewModel));
  }

  ready(_requestId: string): Promise<void> {
    return Promise.resolve();
  }

  failed(failure: FrontendFailure): Promise<void> {
    this.failures.push(structuredClone(failure));
    return Promise.resolve();
  }

  submit(submission: DecisionSubmission): Promise<void> {
    this.submissions.push(structuredClone(submission));
    return Promise.resolve();
  }

  dismiss(requestId: string): Promise<void> {
    this.dismissals.push(requestId);
    return Promise.resolve();
  }
}

export function previewBridge(): PreviewDecisionBridge {
  return new PreviewDecisionBridge(fixtureFromLocation(window.location));
}
