import { isTauri } from "@tauri-apps/api/core";
import type { DecisionBridge } from "./contracts";
import { previewBridge } from "./preview-bridge";
import { TauriDecisionBridge } from "./tauri-bridge";

export function createDecisionBridge(): DecisionBridge {
  return isTauri() ? new TauriDecisionBridge() : previewBridge();
}
