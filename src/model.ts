export type ProcessEngine = 'gitleaks' | 'osv' | 'codex-security';
export type Engine = ProcessEngine | 'runtime-advisories' | 'trivy';
export type Gate = 'PASS' | 'FAIL' | 'REVIEW' | 'INCOMPLETE' | 'ERROR';
export type Execution = 'completed' | 'failed' | 'cancelled' | 'budget_exceeded' | 'not_started';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';
export interface Tool { path: string; sha256: string; version: string }
export interface RunnerConfig {
  codex: Tool; linuxCodex: Tool; docker: Tool; image: string; authHome: string;
  disabledMcpServers: string[]; disabledPlugins: string[];
}
export interface AiLimits {
  maxRequests: number; maxTotalOutputTokens: number; maxOutputTokensPerRequest: number;
  maxInputBytesPerRequest: number; maxResponseBytesPerRequest: number;
  maxToolCalls: number; maxToolResultBytes: number; timeoutMs: number;
}
export interface AiIpcLimits { maxFrameBytes: number; maxBytes: number; maxFrames: number }
export interface AiWorkerResources { cpuCount: number; memoryBytes: number; tmpBytes: number; workBytes: number; shmBytes: number }
export interface WorkerResourceSnapshot {
  kernel: { cpuQuota: number; cpuPeriod: number; memoryMax: number; swapMax: number; tmpBytes: number; workBytes: number; shmBytes: number };
  events: { cpuThrottledPeriods: number; oom: number; oomKill: number };
}
interface WorkerResourceCommon {
  schema: 'scanmux.worker-resources/v1'; requested: AiWorkerResources; exceeded: ('memory' | 'disk' | 'time')[];
}
export type WorkerResourceReport = WorkerResourceCommon & (
  { state: 'not_verified'; reason: 'not_started' | 'boundary_unverified' | 'observation_missing'; kernel: null; events: null; terminal: { exitCode: number; oomKilled: boolean } | null }
  | { state: 'verified'; kernel: WorkerResourceSnapshot['kernel']; events: WorkerResourceSnapshot['events']; terminal: { exitCode: number; oomKilled: boolean } }
);
export interface AiConfig {
  assetsRoot: string; credentialStore: string; limits: AiLimits; ipc: AiIpcLimits;
  workerResources: AiWorkerResources;
  cleanupTimeoutMs: number; commandTimeoutMs: number; reasoningEffort: 'high';
}
interface ConfigFields {
  timeoutMs: number; maxOutputBytes: number; maxFileBytes: number;
  maxSnapshotBytes: number; maxFiles: number; maxCopyBytes?: number; maxJobDiskBytes?: number;
  tools: Partial<Record<'git' | ProcessEngine | 'windows-process-owner' | 'trivy', Tool>>;
  osvDatabase: string | null;
  auth: 'chatgpt'; model: string; accessProgram: 'daybreak_blue';
  runner: RunnerConfig | null;
  ai: AiConfig | null;
}
export interface Config1 extends ConfigFields { schema: 1; runtimePolicy?: never }
export interface Config2 extends ConfigFields { schema: 2; runtimePolicy: import('./runtime-policy.ts').RuntimePolicy }
export type Config = Config1 | Config2;
export interface AiPlan {
  schema: 'scanmux.ai-plan/v2'; provider: 'openai'; endpoint: 'wss://api.openai.com/v1/responses';
  authentication: 'chatgpt'; model: 'gpt-6-sol'; accessProgram: 'daybreak_blue'; reasoningEffort: 'high';
  source: { snapshotHash: string; manifestSha256: string; files: number; bytes: number };
  runtime: { host: 'win32'; worker: 'linux'; sdkVersion: '0.5.1'; pluginVersion: '0.1.95'; imageDigest: string; assetManifestSha256: string };
  limits: AiLimits; ipc: AiIpcLimits; executionTimeoutMs: number; cleanupTimeoutMs: number; commandTimeoutMs: number;
  workerResources: AiWorkerResources;
  parallelism: 1; automaticRetries: 0; automaticRefresh: false;
  retention: { store: false; providerRetention: 'unverified'; trainingPolicy: 'unverified' };
  cost: { amount: null; kind: 'not_applicable'; allowance: 'unknown' };
}
export type DestinationLevel = 'publisher_verified_at_admission' | 'ledger_recorded_at_admission' | 'digest_pinned_only' | 'unidentified';
export type AiLocalComponent = 'codex-security-sdk' | 'linux-image' | 'docker' | 'git' | 'node';
export type Destination = { side: 'local'; component: AiLocalComponent; sha256: string | null; level: DestinationLevel }
  | { side: 'provider'; component: 'openai-responses'; attestation: 'unattestable'; reason: 'provider_offers_no_software_attestation' };
export interface Destinations {
  schema: 'scanmux.destinations/v1'; rule: 'send_only_to_validated_software'; ruleMet: false; destinations: Destination[];
}
export interface FileEntry { path: string; oid: string; bytes: number; sha256: string }
export interface CommitPair { base: string; head: string }
export interface Comparison {
  schema: 'scanmux.comparison/v1'; baseCommit: string; headCommit: string;
  baseTree: string; headTree: string; scope: 'full_head'; baseline: 'not_compared';
  changes: { path: string; kind: 'added' | 'deleted' | 'modified' | 'mode_changed' }[];
}
export type ConfigurationSignalKind = 'node_manifest' | 'node_build_script_declared' | 'python_build_manifest'
  | 'makefile' | 'cmake_manifest' | 'go_module' | 'rust_manifest' | 'jvm_build_manifest' | 'dotnet_project'
  | 'node_os_constraint_declared' | 'container_definition' | 'native_binding_definition' | 'posix_shell_file'
  | 'powershell_file' | 'node_workspaces_declared' | 'pnpm_workspace_file' | 'go_workspace_file'
  | 'monorepo_tool_config' | 'generated_directory_hint' | 'generated_header_declaration';
export type ConfigurationIssueReason = 'invalid_utf8' | 'invalid_json' | 'unsupported_manifest_shape';
export interface ConfigurationAxis {
  state: 'signals_observed' | 'unknown'; signals: { kind: ConfigurationSignalKind; path: string }[];
}
export interface ConfigurationInventory {
  schema: 'scanmux.configuration/v1'; basis: 'accepted_commit_blobs'; interpretation: 'declaration_hints_only';
  build: ConfigurationAxis; osDependencies: ConfigurationAxis; monorepo: ConfigurationAxis; generated: ConfigurationAxis;
  issues: { path: string; reason: ConfigurationIssueReason }[];
  limitations: ('absence_not_proven' | 'build_not_executed' | 'os_requirements_unverified'
    | 'workspace_membership_unverified' | 'generated_status_unverified')[];
}
export type NonEmpty<T> = readonly [T, ...T[]];
export type IaCKind = 'dockerfile' | 'kubernetes' | 'terraform' | 'cloudformation' | 'helm';
export interface InputUnit { key: string; kind: IaCKind | 'unresolved'; files: NonEmpty<string>; unresolved: boolean }
export interface TrivyPlan { schema: 'scanmux.trivy-plan/v1'; profile: 'embedded-config-v1'; inputs: readonly InputUnit[] }
export interface TrivyReceipt { unit: string; state: 'analyzed' | 'unsupported' | 'parse_failed' | 'excluded' | 'unresolved' }
export type TrivyCoverage =
  | { state: 'analyzed'; receipts: NonEmpty<TrivyReceipt & { state: 'analyzed' }> }
  | { state: 'unsupported'; reason: 'no_recognized_config' | 'offline_scope_unavailable' }
  | { state: 'partial'; receipts: readonly TrivyReceipt[]; reasons: NonEmpty<string> };
interface PlanFields {
  source?: { kind: 'public-github'; url: string; commit: string };
  repoId: string; root: string; commit: string | null;
  advisoryCatalog: { schema: 'scanmux.advisories/v1'; asOf: string; sha256: string };
  treeHash: string | null; snapshotHash: string; dirty: boolean | null;
  files: FileEntry[]; exclusions: { path: string; reason: string }[];
  blockers: string[]; languages: string[]; lockfiles: string[];
  configuration?: ConfigurationInventory;
  comparison?: Comparison;
  required: Engine[]; policyHash: string; planHash: string;
  network: 'offline' | 'osv' | 'openai-responses'; transmissions: string[];
  constraints: string[]; cost: { kind: 'not_applicable'; aiCalls: number };
  ai?: AiPlan;
  destinations?: Destinations;
}
export interface PlanV2 extends PlanFields { schema: 'scanmux.plan/v2'; trivy?: never }
export interface PlanV3 extends PlanFields { schema: 'scanmux.plan/v3'; trivy: TrivyPlan }
export type Plan = PlanV2 | PlanV3;
interface FindingFields {
  fingerprint: string; engine: Engine; originIds: string[];
  severity: Severity;
  confidence: 'high' | 'medium' | 'low' | 'unknown';
  evidenceState: 'candidate' | 'source_supported' | 'runtime_reproduced';
  disposition: 'open'; line: number | null;
  title: string; package?: { name: string; version: string; ecosystem: string; direct: 'unknown' };
  fixedVersions: string[]; reachability: 'unknown'; knownExploited: 'unknown';
  advisory?: import('./advisory-catalog.ts').Advisory;
}
export interface LegacyFinding extends FindingFields { engine: Exclude<Engine, 'trivy'>; category: 'secret' | 'dependency' | 'code' | 'runtime'; file: string; endLine?: never }
export interface TrivyFinding extends FindingFields { engine: 'trivy'; category: 'misconfiguration'; evidenceState: 'candidate'; file: string | null; endLine: number | null }
export type Finding = LegacyFinding | TrivyFinding;
export type DeclarationReason = 'exact_declaration' | 'invalid_version' | 'ambiguous_declaration' | 'unsupported_docker_syntax'
  | 'unsupported_image' | 'unsupported_image_variant' | 'dynamic_image' | 'npm_alias' | 'npm_link' | 'npm_source' | 'npm_entry_ambiguous';
export interface Declaration {
  product: import('./advisory-catalog.ts').Product | null; version: string | null; file: string; line: number | null;
  selector: string | null; edition: 'ce' | 'ee' | null; reason: DeclarationReason;
  assessments: { id: string; state: 'matched' | 'outside_recorded_ranges' | 'unknown'; reason: 'affected_version' | 'outside_recorded_ranges' | 'comparison_domain_unknown' | 'declaration_unknown' }[];
}
export interface AdvisoryDetails {
  catalog: Plan['advisoryCatalog']; declarations: Declaration[]; advisories: import('./advisory-catalog.ts').Advisory[];
  environment: 'unverified'; vendorPatches: 'unverified';
}
export interface Evidence {
  kind: 'scanner_observation'; snapshotHash: string; reportHash: string;
  classification: 'confidential'; rawRetained: false;
}
export interface TokenUsage { inputTokens: number; outputTokens: number; totalTokens: number }
export type TokenObservation = { kind: 'unknown'; observed: null }
  | { kind: 'complete' | 'partial'; observed: TokenUsage };
export interface AiTransportFirstEvent {
  kind: 'object' | 'non_object' | 'invalid_json'; type: string; keys: string[]; otherKeys: number;
  sequenceNumber: 'integer' | 'absent' | 'string' | 'number' | 'object' | 'boolean'; sequence: AiTransportFirstEvent['sequenceNumber'];
  streamId: 'absent' | 'null' | 'present';
}
export type AiTransportValueType = 'absent' | 'null' | 'array' | 'string' | 'number' | 'boolean' | 'object';
export interface AiTransportValueShape { type: AiTransportValueType; size: number | null }
export interface AiTransportRejectedEvent extends AiTransportFirstEvent {
  valueShapes?: Record<string, AiTransportValueShape & { output?: AiTransportValueShape; statusType?: AiTransportValueType; keys?: string[]; otherKeys?: number }>;
}
export interface AiExecution {
  schema: 'scanmux.ai-execution/v2'; classification: 'provider' | 'synthetic';
  attemptId: string; originalCommit: string; derivedRevision: string | null; snapshotHash: string;
  sourcePreflight: 'not_completed' | 'completed'; manifestSha256: string;
  status: 'not_started' | 'completed' | 'failed' | 'canceled' | 'budget_exceeded' | 'acceptance_unknown';
  reason: string; artifactsAccepted: boolean;
  mcpEvidence: 'not_started' | 'unverified' | 'closed'; artifactEvidence: 'none' | 'unverified' | 'verified';
  submitInvocations: number; connectionAttempts: number; sendInvocations: number;
  transportRequests?: { sequence: number; receivedBytes: number; receivedMessages: number; firstEvent?: AiTransportFirstEvent | null;
    rejectedEvent?: AiTransportRejectedEvent | null; rejectedAt?: number | null;
    terminal: boolean; terminalKind: 'completed' | 'incomplete' | 'failed' | 'none'; closeCode: number | null; sendOk: boolean; failureCode: string | null;
    providerErrorCode?: string; incompleteReason?: 'max_output_tokens' | 'max_messages' | 'content_filter' | 'steered';
    outputIdentityMismatch?: { streamedItemCount: number; terminalOutputLength: number; index: number; kind: 'missing_index' | 'type' | 'id' | 'call' | 'name';
      streamedType: 'message' | 'function_call' | 'reasoning' | 'other' | null; terminalType: 'message' | 'function_call' | 'reasoning' | 'other' | null } }[];
  tokens: TokenObservation; usageRecords: { sequence: number; usage: TokenUsage }[];
  programs: ('daybreak_blue' | 'standard' | 'daybreak_red' | 'unknown')[]; models: string[];
  cleanup: { closed: boolean; quiescent: boolean; containerAbsent: boolean };
  runtime: { imageDigest: string; boundaryVerified: boolean; resources: WorkerResourceReport; sdkInitializationObservation?: {
    schema: 'scanmux.sdk-initialization-observation/v2'; state: 'observed' | 'unavailable'; helperInvocations: number; closedInvocations: number;
    sqliteFullObserved: boolean; otherSqliteErrorObserved: boolean; terminal: 'none' | 'sqlite_full' | 'other';
  } };
  coverage: { artifactsReviewed: number; exclusions: number; deferred: number; openQuestions: number; limitations: number; sha256: string } | null;
  artifacts: { path: string; bytes: number; sha256: string }[];
  sdkOutcome?: AiSdkOutcome;
}
/** Content-free summary of how the hosted SDK run ended. Unknown codes and tool names read `other`. */
export interface AiSdkOutcome {
  executorStatus: 'completed' | 'failed' | 'canceled' | 'acceptance_unknown' | 'other' | null; executorMessage: string | null;
  sessionStatus: 'completed' | 'failed' | 'canceled' | 'acceptance_unknown' | 'budget_exceeded' | 'other' | null; sessionReason: string | null;
  finalDraft: boolean; writeStarted: boolean; ignoredAfterFinal: number; draftRejections: Partial<Record<Exclude<AiToolFailureCode, 'other'>, number>>; toolInvocations: number; toolFailureCode: AiToolFailureCode | null;
  responses: { sequence: number; toolCalls: number; tools: ('scanmux_read_source' | 'record_codex_security_scan_draft' | 'other')[] }[];
  workerSite: 'result_not_completed' | 'worker_threw' | null; workerErrorCode: string | null;
}
export type AiToolFailureCode = 'source_request' | 'source_result_limit' | 'draft_after_final' | 'draft_shape' | 'draft_owned_field' | 'draft_source' | 'draft_unread_source'
  | 'draft_location' | 'draft_lines' | 'draft_code' | 'draft_locations' | 'draft_writeup' | 'draft_result' | 'draft_result_conflict' | 'draft_receipt' | 'draft_result_limit' | 'secret_check_failed'
  | 'executor_stopped' | 'deadline' | 'canceled' | 'invalid_bytes' | 'invalid_utf8' | 'mcp_unsettled' | 'mcp_unavailable' | 'mcp_input_limit' | 'mcp_response_error'
  | 'bridge_stopped' | 'bridge_mcp_stopped' | 'bridge_mcp_overlap' | 'bridge_mcp_state' | 'bridge_mcp_failed' | 'worker_mcp_failed' | 'other';
export interface EngineRun {
  engine: Engine; execution: Execution;
  coverage: 'analyzed' | 'unsupported' | 'skipped' | 'partial';
  targets: string[]; exclusions: string[]; findings: Finding[]; evidence: Evidence[];
  errors: string[]; version: string | null; executableHash: string | null;
  rulesVersion: string | null; dbAsOf: null; database: { ecosystem: string; sha256: string; modifiedAt: string; provenance?: import('./osv-database.ts').DatabaseProvenance }[];
  startedAt: string; endedAt: string; exitCode: number | null;
  auth: 'none' | 'chatgpt'; modelRequested: string | null; modelActual: string | null;
  accessProgramRequested: 'daybreak_blue' | null; accessProgramEffective: 'daybreak_blue' | 'standard' | 'daybreak_red' | 'unknown' | null;
  usage: { calls: number; cost: null; kind: 'not_applicable' | 'unknown'; allowance: 'unknown' };
  advisoryDetails?: AdvisoryDetails;
  trivyCoverage?: TrivyCoverage;
  aiExecution?: AiExecution;
}
export interface Report {
  schema: 'scanmux.report/v2' | 'scanmux.report/v3'; runId: string; plan: Plan;
  runner: { platform: string; node: string; imageDigest: string | null; isolation: 'local-static-only' | 'host-relay-readonly-linux' | 'host-relay-linux-unverified' };
  startedAt: string; endedAt: string; engines: EngineRun[];
  executionState: Execution; coverageState: 'complete' | 'incomplete';
  gate: Gate; exitCode: number; reasons: string[]; integrityErrors: string[];
}
export interface Capability {
  engine: Engine; category: string; inputs: string[]; operatingSystems: string[];
  permissions: string[]; buildRequired: false; transmission: string; license: string;
}
export interface AdapterContext {
  plan: Plan; config: Config; snapshot: string; workspace: string; copyBudget?: import('./copy-budget.ts').CopyBudget;
  signal: AbortSignal; secretsCleared: boolean;
  secretScan?: EngineRun;
}
export interface Adapter {
  capabilities(): Capability;
  plan(plan: Plan): { applicable: boolean; targets: string[]; constraints: string[] };
  run(context: AdapterContext): Promise<EngineRun>;
  cancel(): void;
  normalize(raw: unknown, context: AdapterContext): Finding[];
  validate(): 'unsupported'; patch(): 'unsupported';
}
