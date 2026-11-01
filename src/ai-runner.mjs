import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
import { projectRepository } from '../internal/projected-repository.mjs';
import { runHostedBridge } from '../internal/hosted-bridge.mjs';
import { openLinuxHostedWorker } from '../internal/linux-hosted-runner.mjs';
import { createResponsesTransport } from '../internal/responses-transport.mjs';
import { emptyRun, normalizeProjectedCodex } from './adapters.ts';
import { aiRuntime, buildAiPlan, verifyAiPlan } from './ai-plan.ts';
import { buildPlan, verifySnapshot } from './repository.ts';
import { checkedText } from './output.ts';
import { digest, hash, SafeError, within } from './safety.ts';
import { active, canonicalAiPath, inventoryAiDirectory, readAiJson } from './ai-files.mjs';
import { readSiwcCredentials } from './siwc-credentials.mjs';
import { hostUsage, readHostTerminals, readAiArtifacts, validateAiArtifactDocuments } from './ai-observations.mjs';
import { workerResourcesComplete, classifyResourceStop } from '../internal/worker-resources.mjs';
import { sourceCleanupFor } from './source-cleanup.ts';

const requireValue = (value, code) => { if (!value) throw new SafeError(code); };
const counter = value => Number.isSafeInteger(value) && value >= 0;
const credentialFailureCodes = new Set(['ai_credentials_permissions', 'ai_credentials_stopped', 'ai_credentials_termination_unverified',
  'ai_credentials_unavailable', 'ai_credentials_locked', 'ai_credentials_control', 'ai_credentials_unverified', 'ai_credentials_expired']);
/** A trusted composition seam. Supplying dependencies always marks evidence synthetic. */
export function createAiAdapter({ acceptedPlanHash, expiresAt, runtime }) {
  requireValue(typeof acceptedPlanHash === 'string' && /^[a-f0-9]{64}$/.test(acceptedPlanHash) && Number.isFinite(expiresAt), 'ai_adapter_options');
  requireValue(runtime === undefined || runtime && typeof runtime === 'object' && Object.keys(runtime).every(key => ['createSocket','openWorker'].includes(key)) && Object.values(runtime).every(value => typeof value === 'function'), 'ai_adapter_dependencies');
  const classification = runtime === undefined ? 'provider' : 'synthetic', cancellation = new AbortController(); let used = false;
  return {
    capabilities: () => ({ engine: 'codex-security', category: 'code', inputs: ['accepted tracked text snapshot'], operatingSystems: ['Windows host; isolated Linux SDK worker'], permissions: ['read-only source projection','dedicated host-only credential relay'], buildRequired: false, transmission: 'fixed OpenAI Responses; exact AI Plan acceptance required', license: 'Apache-2.0; provider and SDK terms separate' }),
    plan: plan => ({ applicable: Boolean(plan.ai), targets: plan.files.map(file => file.path), constraints: ['exact_ai_plan_acceptance_required'] }),
    cancel() { cancellation.abort(); }, validate: () => 'unsupported', patch: () => 'unsupported', normalize: () => { throw new SafeError('ai_projection_required'); },
    async run(context) {
      const run = emptyRun('codex-security', context), options = context.config.ai;
      run.version = null; run.executableHash = null;
      const signal = AbortSignal.any([context.signal, cancellation.signal]), attemptId = randomUUID(), identity = { runId: randomUUID(), attemptId, buildId: digest({ contract: 'scanmux.ai/v2', runtime: aiRuntime }) };
      const state = { schema: 'scanmux.ai-execution/v2', classification, attemptId, originalCommit: context.plan.commit, derivedRevision: null, snapshotHash: context.plan.snapshotHash,
        sourcePreflight: 'not_completed', manifestSha256: context.plan.ai?.source.manifestSha256 ?? digest([]), status: 'not_started', reason: 'ai_not_started', artifactsAccepted: false, mcpEvidence: 'not_started', artifactEvidence: 'none',
        submitInvocations: 0, connectionAttempts: 0, sendInvocations: 0, transportRequests: [], tokens: { kind: 'unknown', observed: null }, usageRecords: [], programs: [], models: [],
        cleanup: { closed: true, quiescent: true, containerAbsent: true }, runtime: { imageDigest: aiRuntime.imageDigest, boundaryVerified: false,
          resources: { schema: 'scanmux.worker-resources/v1', requested: structuredClone(options?.workerResources), state: 'not_verified', reason: 'not_started', kernel: null, events: null, terminal: null, exceeded: [] } }, coverage: null, artifacts: [] };
      run.aiExecution = state; let owner, transport, credentials, result, directory, projection, transportClosed = true;
      const control = { signal, expiresAt, commandTimeoutMs: options?.commandTimeoutMs, cleanupTimeoutMs: options?.cleanupTimeoutMs };
      const errorCode = error => error instanceof SafeError ? error.code : 'ai_execution_failed';
      try {
        requireValue(!used, 'ai_adapter_already_used'); used = true; verifyAiPlan(context.plan, context.config, acceptedPlanHash); active(control);
        requireValue(process.platform === 'win32', 'ai_host_unsupported');
        requireValue(context.secretScan?.execution === 'completed' && context.secretScan.findings.length === 0
          && (context.secretScan.coverage === 'analyzed' || context.secretScan.coverage === 'partial' && context.secretScan.errors.every(code => code === 'builtin_rules_exclude_paths')), 'ai_source_secret_scan_missing');
        for (const isolated of [options.assetsRoot, options.credentialStore]) {
          await canonicalAiPath(isolated, control, 'directory');
          requireValue(!within(isolated, context.plan.root) && !within(context.plan.root, isolated) && !within(isolated, context.workspace) && !within(context.workspace, isolated), 'ai_path_overlap');
        }
        requireValue(!within(options.assetsRoot, options.credentialStore) && !within(options.credentialStore, options.assetsRoot), 'ai_credentials_in_runtime');
        requireValue(await verifySnapshot(context.plan, context.snapshot), 'ai_snapshot_changed'); active(control);
        const assetManifest = await inventoryAiDirectory(options.assetsRoot, control, { maxReceiptBytes: context.config.maxOutputBytes, order: 'sdk-assets' });
        requireValue(assetManifest.length === 10805 && digest(assetManifest) === aiRuntime.assetManifestSha256, 'ai_assets_identity');
        run.version = '0.5.1';
        projection = await projectRepository({ plan: context.plan, config: context.config, snapshot: context.snapshot, workspace: context.workspace, signal });
        if (projection.errors?.includes('source_cleanup_failed')) run.errors.push('source_cleanup_failed');
        requireValue(projection.status === 'completed', projection.status === 'termination_unverified' ? 'ai_projection_termination_unverified' : 'ai_projection_failed');
        active(control);
        state.derivedRevision = projection.mapping.derivedRevision;
        const receipts = await inventoryAiDirectory(projection.repository, control, { directories: true, maxReceiptBytes: options.ipc.maxBytes });
        directory = path.join(context.workspace, 'ai-attempt'); await fs.mkdir(directory, { mode: 0o700 }); active(control);
        const check = async (bytes, checkingSignal) => {
          active(control); const copied = Buffer.from(bytes), text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(copied);
          requireValue(Buffer.from(text).equals(copied), 'ai_secret_check_encoding');
          await checkedText(text, { ...context.config, timeoutMs: Math.max(1, Math.floor(expiresAt - performance.now())) }, context.workspace, AbortSignal.any([signal, checkingSignal])); active(control);
          return { bytes: copied.length, sha256: hash(copied) };
        };
        const binding = { repository: '/handoff', revision: projection.mapping.derivedRevision, originalCommit: context.plan.commit, snapshotHash: context.plan.snapshotHash, scope: projection.scope, identity, reasoningEffort: options.reasoningEffort, manifest: projection.mapping.manifest };
        result = await runHostedBridge({ directory, sourceRoot: projection.repository, input: { plan: context.plan, config: context.config, projection: { status: projection.status, mapping: projection.mapping, scope: projection.scope } }, binding,
          limits: options.limits, ipc: options.ipc, workerResources: options.workerResources, timeoutMs: Math.max(1, Math.floor(expiresAt - performance.now())), cleanupTimeoutMs: options.cleanupTimeoutMs, signal, check,
          validateArtifacts(copies, metadata) {
            const artifacts = validateAiArtifactDocuments(copies, metadata, context.plan, options.ipc.maxBytes);
            normalizeProjectedCodex({ manifest: artifacts.manifest, findings: artifacts.findings }, projection.mapping, context);
          },
          async submit(bytes, requestContext) {
            const diagnostic = { sequence: requestContext.sequence, receivedBytes: 0, receivedMessages: 0, firstEvent: null, rejectedEvent: null, rejectedAt: null, terminal: false, terminalKind: 'none', closeCode: null, sendOk: false, failureCode: 'transport_setup' };
            state.transportRequests.push(diagnostic);
            try {
              active(control);
              credentials ??= await readSiwcCredentials(options.credentialStore, control); active(control);
              requireValue(credentials.expiresAt > Date.now(), 'ai_credentials_expired');
              if (!transport) {
                transport = createResponsesTransport({ bearerToken: credentials.accessToken, maxRequests: options.limits.maxRequests, maxRequestBytes: options.limits.maxInputBytesPerRequest,
                  maxResponseBytes: options.limits.maxResponseBytesPerRequest, maxEvents: options.limits.maxResponseBytesPerRequest, timeoutMs: Math.max(1, Math.min(options.limits.timeoutMs, Math.floor(expiresAt - performance.now()))), ...(runtime?.createSocket ? { createSocket: runtime.createSocket } : {}) });
                transportClosed = false;
              }
              active(control); return await transport.submit(bytes, requestContext);
            } catch (error) {
              if (error instanceof SafeError && credentialFailureCodes.has(error.code)) diagnostic.failureCode = error.code;
              throw error;
            }
          },
          async closeTransport(requestContext) { const ending = transport ? await transport.close(requestContext) : { closed: true, quiescent: true }; transportClosed = ending.closed === true && ending.quiescent === true; return ending; },
          async openWorker(workerControl) {
            state.sourcePreflight = 'completed';
            const open = runtime?.openWorker ?? openLinuxHostedWorker;
            owner = await open({ ...workerControl, directory: path.join(directory, 'runner'), sourceRoot: projection.repository,
              assets: { root: options.assetsRoot, manifest: assetManifest, manifestSha256: aiRuntime.assetManifestSha256 }, sourceReceipts: receipts, workerResources: options.workerResources, commandTimeoutMs: options.commandTimeoutMs });
            return owner;
          },
          async verifyInputs({ phase, inputHash }) {
            const cleanupSignal = phase === 'after' ? AbortSignal.timeout(options.cleanupTimeoutMs) : signal;
            const verification = { ...control, signal: cleanupSignal, expiresAt: phase === 'after' ? performance.now() + options.cleanupTimeoutMs : expiresAt };
            const current = await buildPlan(context.plan.root, context.config, context.workspace, cleanupSignal, context.plan.comparison ? { base: context.plan.comparison.baseCommit, head: context.plan.comparison.headCommit } : undefined);
            requireValue(buildAiPlan(current, context.config).planHash === context.plan.planHash && await verifySnapshot(context.plan, context.snapshot), 'ai_source_changed'); active(verification);
            requireValue(isDeepStrictEqual(await inventoryAiDirectory(projection.repository, verification, { directories: true, maxReceiptBytes: options.ipc.maxBytes }), receipts), 'ai_projection_changed');
            requireValue(isDeepStrictEqual(await readAiJson(projection.mappingFile, context.config.maxOutputBytes, verification), projection.mapping), 'ai_projection_changed'); active(verification);
            return { inputHash };
          },
        });
        state.status = result.status; state.reason = result.reason; state.cleanup = result.cleanup ?? state.cleanup; state.mcpEvidence = result.mcpEvidence; state.artifactEvidence = result.artifactEvidence;
        if (result.workerResources) state.runtime.resources = result.workerResources;
        if (result.sdkInitializationObservation) state.runtime.sdkInitializationObservation = structuredClone(result.sdkInitializationObservation);
        if (result.sdkOutcome) state.sdkOutcome = structuredClone(result.sdkOutcome);
        const usage = hostUsage(result, options.limits.maxRequests); state.submitInvocations = usage.calls; state.tokens = usage.tokens; state.usageRecords = usage.records.map(({ sequence, usage }) => ({ sequence, usage })); run.usage.calls = usage.calls;
        const post = { ...control, signal: AbortSignal.timeout(options.cleanupTimeoutMs), expiresAt: performance.now() + options.cleanupTimeoutMs };
        try { const terminals = await readHostTerminals({ result, usage, directory, identity, snapshotHash: context.plan.snapshotHash, maximumBytes: context.config.maxOutputBytes, control: post }); state.tokens = terminals.tokens; state.programs = terminals.programs; state.models = terminals.models; }
        catch { state.status = 'acceptance_unknown'; state.reason = 'ai_usage_records_incomplete'; run.errors.push('ai_usage_records_incomplete'); }
        if (classification === 'provider') {
          run.modelActual = state.models.length === 1 ? state.models[0] : null;
          run.accessProgramEffective = state.programs.length === 1 ? state.programs[0] : 'unknown';
        }
        if (state.programs.some(program => program !== 'daybreak_blue' && program !== 'standard')) run.errors.push('ai_effective_program_unverified');
        if (result.artifactsAccepted && !run.errors.length && workerResourcesComplete(state.runtime.resources, options.workerResources)) {
          const artifacts = await readAiArtifacts(result, directory, context.plan, post, options.ipc.maxBytes);
          run.findings = normalizeProjectedCodex({ manifest: artifacts.manifest, findings: artifacts.findings }, projection.mapping, context);
          state.artifactsAccepted = true; state.artifacts = artifacts.descriptors; state.coverage = artifacts.observation; run.errors.push(...artifacts.reasons);
          run.evidence = [{ kind: 'scanner_observation', snapshotHash: context.plan.snapshotHash, reportHash: digest(artifacts.descriptors), classification: 'confidential', rawRetained: false }];
          run.execution = 'completed'; run.coverage = artifacts.reasons.length || classification === 'synthetic' ? 'partial' : 'analyzed';
        } else {
          run.execution = signal.aborted ? 'cancelled' : state.status === 'budget_exceeded' ? 'budget_exceeded' : 'failed'; run.coverage = 'partial'; run.errors.push(state.reason);
        }
      } catch (error) {
        state.reason = errorCode(error); state.status = signal.aborted ? 'canceled' : 'failed'; run.execution = signal.aborted ? 'cancelled' : 'failed'; run.coverage = 'partial'; run.errors.push(state.reason);
      } finally {
        credentials = undefined;
        if (transport) {
          const observed = transport.inspect();
          const requests = new Map(observed.calls.map(({ sequence, receivedBytes, receivedMessages, firstEvent, rejectedEvent, rejectedAt, terminalKind, closeCode, sendOk, failureCode, providerErrorCode, incompleteReason, outputIdentityMismatch }) =>
            [sequence, { sequence, receivedBytes, receivedMessages, firstEvent, rejectedEvent, rejectedAt, terminal: terminalKind !== 'none', terminalKind, closeCode, sendOk, failureCode,
              ...(providerErrorCode === undefined ? {} : { providerErrorCode }), ...(incompleteReason === undefined ? {} : { incompleteReason }), ...(outputIdentityMismatch == null ? {} : { outputIdentityMismatch }) }]));
          state.transportRequests = state.transportRequests.map(row => requests.get(row.sequence) ?? row);
          if ([observed.connectionAttempts, observed.sendInvocations].every(counter) && observed.sendInvocations <= observed.connectionAttempts && observed.connectionAttempts <= state.submitInvocations) { state.connectionAttempts = observed.connectionAttempts; state.sendInvocations = observed.sendInvocations; }
          else { run.errors.push('ai_transport_observation_invalid'); run.execution = 'failed'; run.coverage = 'partial'; state.artifactsAccepted = false; run.findings = []; }
        }
        const diagnostics = owner?.diagnostics?.(); state.runtime.boundaryVerified = diagnostics?.boundaryVerifiedBeforeStart === true && diagnostics.imageId === aiRuntime.imageDigest;
        const resourceReason = classifyResourceStop({ resources: state.runtime.resources, reason: result?.reason, boundaryVerified: state.runtime.boundaryVerified,
          inputsUnchanged: result?.inputsUnchanged, workerClosed: state.cleanup.closed, containerAbsent: state.cleanup.containerAbsent, transportClosed,
          calls: state.submitInvocations, tokensComplete: state.tokens.kind === 'complete', executionStatus: result?.execution?.status,
          mcpEvidence: result?.mcpEvidence, artifactEvidence: result?.artifactEvidence,
          independentFailure: run.errors.some(code => code !== result?.reason) || (result?.independentFailures?.length ?? 0) > 0 || ['resource_boundary_unverified', 'resource_observation_invalid'].includes(diagnostics?.failureCode) });
        if (result?.independentFailures?.length) run.errors.push(...result.independentFailures);
        if (resourceReason) {
          state.status = 'budget_exceeded'; state.reason = resourceReason; state.artifactsAccepted = false; state.artifacts = []; state.coverage = null;
          run.execution = 'budget_exceeded'; run.coverage = 'partial'; run.findings = []; run.evidence = []; run.errors.push(resourceReason);
        }
        if (run.coverage === 'analyzed' && !state.runtime.boundaryVerified) { run.errors.push('ai_boundary_unverified'); run.execution = 'failed'; run.coverage = 'partial'; state.artifactsAccepted = false; run.findings = []; }
        if (owner && (!state.cleanup.closed || !state.cleanup.containerAbsent || !state.cleanup.quiescent && !resourceReason) || result?.workerAttempted && !owner) run.errors.push('ai_closure_termination_unverified');
        if (classification === 'synthetic') run.errors.push('ai_synthetic_evidence');
        if (context.workspace && (await sourceCleanupFor(context.workspace).cleanup(context.workspace, ['sdk-repository', 'sdk-projection-control'].map(name => path.join(context.workspace, name)))).status === 'failed') {
          run.execution = 'failed'; run.errors.push('source_cleanup_failed');
        }
        run.endedAt = new Date().toISOString(); run.errors = [...new Set(run.errors)];
      }
      return run;
    },
  };
}
