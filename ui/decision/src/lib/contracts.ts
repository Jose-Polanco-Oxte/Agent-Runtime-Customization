export type UiTheme = "light" | "dark";
export type DecisionIntent = "allow" | "deny";
export type FrontendFailureStage = "load_request" | "render_or_ready";
export type FrontendFailureCode =
  | "invoke_rejected"
  | "invalid_payload"
  | "render_failed"
  | "unknown";

export type DialogPresentationKind =
  | "guard_failures"
  | "exact_operation_authorization"
  | "aggregate_decision";

export interface DialogFailedProbe {
  rule_name?: string | null;
  command: string;
  reason?: string | null;
}

export interface DialogViolationItem {
  guard_id: string;
  summary: string;
  configured_feedback?: string | null;
  auditor_findings?: string | null;
  scope: string;
  failed_probes?: DialogFailedProbe[];
}

export interface DialogAuthorizationItem {
  guard_id: string;
  summary: string;
  auditor_findings?: string | null;
  operation_fingerprint: string;
}

export interface DialogRequest {
  schema: "arc.decision.dialog.request.v2";
  request_id: string;
  presentation_kind: DialogPresentationKind;
  title: string;
  scope: string;
  violations: DialogViolationItem[];
  authorizations: DialogAuthorizationItem[];
  operation: string | null;
  bundle_fingerprint: string;
  expires_at_unix_ms: number;
}

export const DIALOG_LIMITS = {
  id: 256,
  title: 256,
  scope: 2048,
  summary: 512,
  operation: 4096,
  feedback: 16 * 1024,
  findings: 16 * 1024,
  failed_probes: 64,
  user_message: 4000,
} as const;

// Rust `str::trim` blank set (Unicode White_Space); JS `trim` differs on U+0085 and U+FEFF.
const RUST_BLANK =
  /^[\t-\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/;
const EXPIRY_EXCLUSIVE_MAX = 2 ** 63;

function codePointLength(value: string): number {
  let count = 0;
  for (const _point of value) count += 1;
  return count;
}

function validateText(value: string, field: string, max: number): void {
  if (RUST_BLANK.test(value)) throw new TypeError(`${field} must be non-empty`);
  if (codePointLength(value) > max) {
    throw new TypeError(`${field} must not exceed ${max} characters`);
  }
}

// Mirrors Rust `contains_unsupported_markup`: `<`, optional `/` or `!`, a letter or `-`, and a later `>`.
function containsUnsupportedMarkup(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    if (value[i] !== "<") continue;
    let j = i + 1;
    if (j < value.length && (value[j] === "/" || value[j] === "!")) j += 1;
    if (j < value.length && /[A-Za-z-]/.test(value[j]) && value.indexOf(">", j) !== -1) {
      return true;
    }
  }
  return false;
}

function validateSummary(value: string, field: string): void {
  validateText(value, field, DIALOG_LIMITS.summary);
  if (containsUnsupportedMarkup(value)) {
    throw new TypeError(`${field} contains unsupported markup`);
  }
}

function validateOptionalViolationText(
  value: string | null | undefined,
  field: string,
  max: number,
): void {
  if (value == null) return;
  validateText(value, field, max);
  if (value.includes("<") || value.includes(">")) {
    throw new TypeError(`${field} must not contain unsupported markup`);
  }
}

function validateFailedProbes(probes: DialogFailedProbe[] | undefined): void {
  if (probes === undefined) return;
  if (probes.length > DIALOG_LIMITS.failed_probes) {
    throw new TypeError(
      `violations.failed_probes must not exceed ${DIALOG_LIMITS.failed_probes} entries`,
    );
  }
  for (const probe of probes) {
    validateText(probe.command, "violations.failed_probes.command", DIALOG_LIMITS.id);
    if (probe.rule_name != null) {
      validateText(probe.rule_name, "violations.failed_probes.rule_name", DIALOG_LIMITS.id);
    }
    if (probe.reason != null) {
      validateSummary(probe.reason, "violations.failed_probes.reason");
    }
  }
}

export function dialogGuardIds(request: DialogRequest): string[] {
  const ids = new Set<string>();
  for (const violation of request.violations) {
    ids.add(violation.guard_id);
  }
  for (const auth of request.authorizations) {
    ids.add(auth.guard_id);
  }
  return Array.from(ids);
}

export function dialogOperation(request: DialogRequest): string | null {
  return request.operation;
}

export function validateDialogRequest(request: DialogRequest): void {
  if (request.schema !== "arc.decision.dialog.request.v2") throw new TypeError("invalid request schema");
  validateText(request.request_id, "request_id", DIALOG_LIMITS.id);
  validateText(request.title, "title", DIALOG_LIMITS.title);
  validateText(request.scope, "scope", DIALOG_LIMITS.scope);
  validateText(request.bundle_fingerprint, "bundle_fingerprint", DIALOG_LIMITS.id);
  const expiry = request.expires_at_unix_ms;
  if (!(Number.isInteger(expiry) && expiry >= 0 && expiry < EXPIRY_EXCLUSIVE_MAX)) {
    throw new TypeError("expires_at_unix_ms must be an integer in [0, 2^63)");
  }
  const ids = new Set<string>();
  for (const violation of request.violations) {
    validateText(violation.guard_id, "violations.guard_id", DIALOG_LIMITS.id);
    validateSummary(violation.summary, "violations.summary");
    validateOptionalViolationText(
      violation.configured_feedback,
      "configured feedback",
      DIALOG_LIMITS.feedback,
    );
    validateOptionalViolationText(
      violation.auditor_findings,
      "auditor findings",
      DIALOG_LIMITS.findings,
    );
    validateText(violation.scope, "violations.scope", DIALOG_LIMITS.scope);
    validateFailedProbes(violation.failed_probes);
    if (ids.has(violation.guard_id)) throw new TypeError("duplicate violation guard id");
    ids.add(violation.guard_id);
  }
  if (request.operation != null) {
    validateText(request.operation, "operation", DIALOG_LIMITS.operation);
  }
  const kind: DialogPresentationKind = request.presentation_kind;
  switch (kind) {
    case "guard_failures":
      if (request.violations.length === 0 || request.authorizations.length > 0) {
        throw new TypeError("guard failures require violations and no authorizations");
      }
      break;
    case "exact_operation_authorization":
      if (
        request.violations.length > 0 ||
        request.authorizations.length === 0 ||
        request.operation == null
      ) {
        throw new TypeError("exact authorization requires authorizations and operation");
      }
      break;
    case "aggregate_decision":
      if (request.violations.length === 0 && request.authorizations.length === 0) {
        throw new TypeError("aggregate decision requires violations or authorizations");
      }
      if (request.authorizations.length > 0 && request.operation == null) {
        throw new TypeError("aggregate decision with authorizations requires operation");
      }
      break;
    default:
      throw new TypeError("unknown presentation kind");
  }
  for (const auth of request.authorizations) {
    validateText(auth.guard_id, "authorizations.guard_id", DIALOG_LIMITS.id);
    validateSummary(auth.summary, "authorizations.summary");
    validateOptionalViolationText(auth.auditor_findings, "auditor findings", DIALOG_LIMITS.findings);
    validateText(
      auth.operation_fingerprint,
      "authorizations.operation_fingerprint",
      DIALOG_LIMITS.id,
    );
  }
}

type Shape = Record<string, unknown>;

function asObject(value: unknown, field: string, allowed: readonly string[]): Shape {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${field} must be an object`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new TypeError(`${field} has unknown key ${key}`);
  }
  return value as Shape;
}

function requireString(shape: Shape, key: string, field: string): string {
  const value = shape[key];
  if (typeof value !== "string") throw new TypeError(`${field}.${key} must be a string`);
  return value;
}

function optionalString(shape: Shape, key: string, field: string): void {
  const value = shape[key];
  if (value !== undefined && value !== null && typeof value !== "string") {
    throw new TypeError(`${field}.${key} must be a string or null`);
  }
}

function requireList(shape: Shape, key: string): unknown[] {
  const value = shape[key];
  if (!Array.isArray(value)) throw new TypeError(`${key} must be an array`);
  return value;
}

const REQUEST_KEYS = [
  "schema",
  "request_id",
  "presentation_kind",
  "title",
  "scope",
  "violations",
  "authorizations",
  "operation",
  "bundle_fingerprint",
  "expires_at_unix_ms",
] as const;
const VIOLATION_KEYS = [
  "guard_id",
  "summary",
  "configured_feedback",
  "auditor_findings",
  "scope",
  "failed_probes",
] as const;
const PROBE_KEYS = ["rule_name", "command", "reason"] as const;
const AUTHORIZATION_KEYS = [
  "guard_id",
  "summary",
  "auditor_findings",
  "operation_fingerprint",
] as const;
const KINDS: readonly string[] = [
  "guard_failures",
  "exact_operation_authorization",
  "aggregate_decision",
];

export function parseDialogRequest(value: unknown): DialogRequest {
  const shape = asObject(value, "request", REQUEST_KEYS);
  requireString(shape, "schema", "request");
  requireString(shape, "request_id", "request");
  const kind = requireString(shape, "presentation_kind", "request");
  if (!KINDS.includes(kind)) throw new TypeError("unknown presentation kind");
  requireString(shape, "title", "request");
  requireString(shape, "scope", "request");
  requireString(shape, "bundle_fingerprint", "request");
  if (typeof shape.expires_at_unix_ms !== "number") {
    throw new TypeError("expires_at_unix_ms must be a number");
  }
  if (shape.operation !== undefined && shape.operation !== null && typeof shape.operation !== "string") {
    throw new TypeError("operation must be a string or null");
  }
  for (const item of requireList(shape, "violations")) {
    const violation = asObject(item, "violation", VIOLATION_KEYS);
    requireString(violation, "guard_id", "violation");
    requireString(violation, "summary", "violation");
    requireString(violation, "scope", "violation");
    optionalString(violation, "configured_feedback", "violation");
    optionalString(violation, "auditor_findings", "violation");
    if (violation.failed_probes !== undefined) {
      for (const probeItem of requireList(violation, "failed_probes")) {
        const probe = asObject(probeItem, "failed probe", PROBE_KEYS);
        requireString(probe, "command", "failed probe");
        optionalString(probe, "rule_name", "failed probe");
        optionalString(probe, "reason", "failed probe");
      }
    }
  }
  for (const item of requireList(shape, "authorizations")) {
    const auth = asObject(item, "authorization", AUTHORIZATION_KEYS);
    requireString(auth, "guard_id", "authorization");
    requireString(auth, "summary", "authorization");
    requireString(auth, "operation_fingerprint", "authorization");
    optionalString(auth, "auditor_findings", "authorization");
  }
  const request = { ...shape, operation: shape.operation ?? null } as unknown as DialogRequest;
  validateDialogRequest(request);
  return request;
}

export interface DecisionViewModel {
  request: DialogRequest;
  theme: UiTheme;
  max_user_message_chars: number;
  preview: boolean;
}

export function parseDecisionViewModel(value: unknown): DecisionViewModel {
  const shape = asObject(value, "view model", [
    "request",
    "theme",
    "max_user_message_chars",
    "preview",
  ]);
  const request = parseDialogRequest(shape.request);
  if (shape.theme !== "light" && shape.theme !== "dark") {
    throw new TypeError("theme must be light or dark");
  }
  const max = shape.max_user_message_chars;
  if (
    typeof max !== "number" ||
    !Number.isInteger(max) ||
    max < 1 ||
    max > DIALOG_LIMITS.user_message
  ) {
    throw new TypeError("max_user_message_chars is out of range");
  }
  if (typeof shape.preview !== "boolean") throw new TypeError("preview must be a boolean");
  return { request, theme: shape.theme, max_user_message_chars: max, preview: shape.preview };
}

export interface DecisionSubmission {
  request_id: string;
  decision: DecisionIntent;
  message: string | null;
}

export interface FrontendFailure {
  request_id: string | null;
  stage: FrontendFailureStage;
  code: FrontendFailureCode;
}

export interface DecisionBridge {
  load(): Promise<DecisionViewModel>;
  ready(requestId: string): Promise<void>;
  failed(failure: FrontendFailure): Promise<void>;
  submit(submission: DecisionSubmission): Promise<void>;
  dismiss(requestId: string): Promise<void>;
}

export function classifyFrontendError(error: unknown): FrontendFailureCode {
  if (error instanceof TypeError) return "invalid_payload";
  if (typeof DOMException !== "undefined" && error instanceof DOMException) {
    return "render_failed";
  }
  if (error instanceof Error) return "invoke_rejected";
  return "unknown";
}

export function boundUserMessage(value: string, limit: number): string {
  return Array.from(value).slice(0, Math.max(0, limit)).join("");
}

export function optionalUserMessage(value: string): string | null {
  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
}
