import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import path from 'node:path';
import type { Config, Plan, Report } from './model.ts';
import { githubUrl } from './github.ts';
import { prepareGitHubPlan } from './repository.ts';
import { privateWorkspace } from './private-storage.ts';
import { scan } from './controller.ts';
import { checkedJson, checkedText, saveReportBundle } from './output.ts';
import { reportCsp } from './html-report.ts';
import { advisoryView } from './advisory-display.ts';
import { SafeError } from './safety.ts';
import { html, css, javascript } from './web-ui.ts';
import { checkedSiteOrigin, siteApi, sitePreflight, webAuthority, webContract, type WebObservation } from './web-connection.ts';
import { SourceCleanupOwner, sourceCleanupFailed, withSourceCleanup } from './source-cleanup.ts';
import { decide, exitCodes } from './policy.ts';

type State = 'preparing' | 'planned' | 'blocked' | 'running' | 'cancelling' | 'completed' | 'cancelled' | 'error';
type PlanView = Pick<Plan, 'commit' | 'languages' | 'lockfiles' | 'exclusions' | 'blockers' | 'advisoryCatalog'> & { url: string; files: number };
type ReportView = Pick<Report, 'gate' | 'executionState' | 'coverageState' | 'engines' | 'reasons' | 'integrityErrors'> & { runtimeAdvisories: ReturnType<typeof advisoryView>[] };
interface Job {
  id: string; state: State; phase: string; abort: AbortController; workspace?: string;
  plan?: Plan; view?: PlanView; result?: ReportView; report?: string; htmlReport?: string; error?: string;
  retained: boolean; busy: boolean; started: boolean; pending?: Promise<void>; cleanup: SourceCleanupOwner;
}

// Dependency injection is local code only; no browser request can select a service or config.
export interface WebServices {
  workspace(): Promise<string>;
  prepare: typeof prepareGitHubPlan;
  scan: typeof scan;
  check: typeof checkedJson;
  checkText: typeof checkedText;
}
const services: WebServices = { workspace: privateWorkspace, prepare: prepareGitHubPlan, scan, check: checkedJson, checkText: checkedText };
const publicErrors = new Set(['public_github_fetch_failed', 'public_github_head_unavailable', 'git_timeout',
  'git_output_limit', 'fetch_byte_limit', 'git_not_configured', 'tool_digest_mismatch', 'tool_version_mismatch',
  'output_secret_check_unavailable', 'output_secret_check_failed', 'output_size_limit', 'private_acl_unverified']);

export interface WebOptions {
  siteOrigin?: string;
  observe?(event: WebObservation): Promise<void>;
}

export async function startWeb(input: Config, operations: WebServices = services, options: WebOptions = {}) {
  if (input.tools.trivy) throw new SafeError('trivy_entry_unsupported');
  const config = structuredClone(input);
  const siteOrigin = checkedSiteOrigin(options.siteOrigin);
  const token = randomBytes(32).toString('hex');
  const siteToken = siteOrigin ? randomBytes(32).toString('hex') : undefined;
  let observationState = options.observe ? 'ready' : 'off';
  let origin = '';
  let job: Job | undefined;
  let replacing = false;
  let closing = false;
  type CloseResult = { retained: boolean; workspace: string | undefined };
  const closed = Promise.withResolvers<CloseResult>();
  let closePromise: Promise<CloseResult> | undefined;
  function close(): Promise<CloseResult> {
    closing = true;
    return closePromise ??= (async () => {
      if (job) { cancel(job); await job.pending; await cleanup(job).catch(error => fail(job!, error)); }
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      const result = { retained: Boolean(job?.retained || sourceCleanupFailed()), workspace: job?.workspace };
      closed.resolve(result);
      return result;
    })();
  }

  function view() {
    const session = { contract: webContract, observation: observationState, capabilities: { htmlReport: true } };
    if (!job) return { ...session, state: 'idle', canReplace: !closing && !replacing };
    const state = job.busy ? job.abort.signal.aborted ? 'cancelling' : job.started ? 'running' : 'preparing' : job.state;
    return { ...session, id: job.id, state, phase: job.phase, plan: job.view, result: job.busy ? undefined : job.result,
      error: job.error, retained: job.retained, canReplace: !closing && !replacing && !job.busy && !job.retained,
      reportAvailable: Boolean(job.report && job.htmlReport) && !job.busy };
  }
  async function observe(owned: Job, operation: WebObservation['operation']) {
    if (!options.observe) return;
    // Construct a separate closed projection. No URL, path, report, engine text or input is copied.
    const outcomes: WebObservation['outcome'][] = ['planned', 'blocked', 'completed', 'cancelled', 'error'];
    const gates: WebObservation['gate'][] = ['PASS', 'FAIL', 'REVIEW', 'INCOMPLETE', 'ERROR'];
    const reason = owned.error && (publicErrors.has(owned.error) || ['termination_unverified', 'source_cleanup_failed'].includes(owned.error))
      ? owned.error as WebObservation['reason'] : owned.error ? 'operation_failed' : 'none';
    const event: WebObservation = { schema: 'scanmux.observation/v1', eventId: randomUUID(), at: new Date().toISOString(),
      operation, outcome: outcomes.includes(owned.state as WebObservation['outcome']) ? owned.state as WebObservation['outcome'] : 'error',
      gate: gates.includes(owned.result?.gate as WebObservation['gate']) ? owned.result!.gate : 'not_available', reason, files: owned.plan?.files.length ?? 0,
      findings: owned.result?.engines.reduce((count, engine) => count + engine.findings.length, 0) ?? 0 };
    try { await options.observe(event); observationState = 'ready'; }
    catch { observationState = 'write_failed'; }
  }
  async function cleanup(owned: Job): Promise<void> {
    if (!owned.workspace) return;
    if ((await owned.cleanup.cleanup(owned.workspace)).status === 'failed') {
      owned.retained = true;
      throw new SafeError('source_cleanup_failed');
    }
  }
  function fail(owned: Job, error: unknown): void {
    const code = error instanceof SafeError ? error.code : '';
    if (code.endsWith('termination_unverified')) {
      owned.retained = true;
      owned.error = 'termination_unverified';
    } else if (code === 'source_cleanup_failed') { owned.retained = true; owned.error ??= 'source_cleanup_failed'; }
    else owned.error ??= publicErrors.has(code) ? code : 'operation_failed';
    owned.state = 'error';
  }
  async function prepare(owned: Job, url: string): Promise<void> {
    try {
      owned.workspace = await operations.workspace();
      if (owned.abort.signal.aborted) { owned.state = 'cancelled'; return; }
      const plan = await operations.prepare(url, config, owned.workspace, owned.abort.signal, phase => { owned.phase = phase; });
      if (plan.blockers.some(code => code.endsWith('termination_unverified'))) throw new SafeError('termination_unverified');
      if (owned.abort.signal.aborted) { owned.state = 'cancelled'; return; }
      owned.phase = 'checking_output';
      const projection: PlanView = { url: plan.source?.url ?? url, commit: plan.commit, files: plan.files.length,
        languages: plan.languages, lockfiles: plan.lockfiles, exclusions: plan.exclusions, blockers: plan.blockers, advisoryCatalog: plan.advisoryCatalog };
      const checked = await operations.check(projection, config, owned.workspace);
      if (owned.abort.signal.aborted) { owned.state = 'cancelled'; return; }
      owned.plan = plan;
      owned.view = JSON.parse(checked) as PlanView;
      owned.state = plan.blockers.length ? 'blocked' : 'planned';
    } catch (error) {
      if (error instanceof SafeError && error.code === 'git_cancelled') owned.state = 'cancelled';
      else fail(owned, error);
    } finally {
      if (owned.state !== 'planned') await cleanup(owned).catch(error => fail(owned, error));
      owned.busy = false;
      await observe(owned, 'prepare');
    }
  }
  async function run(owned: Job): Promise<void> {
    try {
      const report = await operations.scan(owned.plan!, config, owned.workspace!, owned.abort.signal);
      if (report.integrityErrors.some(code => code.endsWith('termination_unverified'))) owned.retained = true;
      try { await cleanup(owned); }
      catch (error) { fail(owned, error); }
      if (sourceCleanupFailed()) {
        if (!report.integrityErrors.includes('source_cleanup_failed')) report.integrityErrors.push('source_cleanup_failed');
        const judgment = decide(report.plan, report.engines, report.integrityErrors);
        Object.assign(report, judgment, { executionState: 'failed', exitCode: exitCodes[judgment.gate] });
      }
      owned.phase = 'checking_output';
      const bundle = await saveReportBundle(report, config, owned.workspace!, operations.check, operations.checkText);
      const safe = bundle.report;
      owned.report = bundle.json;
      owned.htmlReport = bundle.html;
      owned.result = { gate: safe.gate, executionState: safe.executionState, coverageState: safe.coverageState,
        engines: safe.engines, reasons: safe.reasons, integrityErrors: safe.integrityErrors,
        runtimeAdvisories: safe.engines.flatMap(run => run.advisoryDetails ? [advisoryView(run.advisoryDetails)] : []) };
      owned.state = owned.retained || safe.executionState === 'failed' ? 'error'
        : safe.executionState === 'cancelled' ? 'cancelled' : 'completed';
      if (report.integrityErrors.some(code => code.endsWith('termination_unverified'))) owned.error = 'termination_unverified';
      else if (report.integrityErrors.includes('source_cleanup_failed')) owned.error ??= 'source_cleanup_failed';
    } catch (error) { fail(owned, error); }
    finally {
      await cleanup(owned).catch(error => fail(owned, error));
      owned.busy = false;
      await observe(owned, 'scan');
    }
  }
  function cancel(owned: Job): void {
    if (owned.busy) owned.abort.abort();
    else if (owned.state === 'planned') {
      owned.abort.abort(); owned.busy = true;
      owned.pending = cleanup(owned).then(() => { owned.state = 'cancelled'; }, error => fail(owned, error))
        .finally(() => { owned.busy = false; });
    }
  }
  function send(res: ServerResponse, status: number, payload: unknown): void {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(payload));
  }
  async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
    let bytes = 0;
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      bytes += chunk.length;
      if (bytes > config.maxOutputBytes) throw new SafeError('request_size');
      chunks.push(chunk);
    }
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new SafeError('request_shape');
    return parsed as Record<string, unknown>;
  }
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    try {
      if (req.headers.host !== new URL(origin).host) {
        send(res, 403, { error: 'request_origin' }); return;
      }
      if (req.method === 'OPTIONS') {
        if (!sitePreflight(req.headers, req.url, origin, siteOrigin)) { send(res, 403, { error: 'request_origin' }); return; }
        res.setHeader('Access-Control-Allow-Origin', siteOrigin!);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Methods', String(req.headers['access-control-request-method']));
        res.setHeader('Access-Control-Allow-Headers', String(req.headers['access-control-request-headers']));
        if (req.headers['access-control-request-private-network'] === 'true') res.setHeader('Access-Control-Allow-Private-Network', 'true');
        res.writeHead(204); res.end(); return;
      }
      const staticFiles: Record<string, [string, string]> = { '/': ['text/html', html], '/app.css': ['text/css', css], '/app.js': ['text/javascript', javascript] };
      const asset = Object.hasOwn(staticFiles, req.url ?? '') ? staticFiles[req.url!] : undefined;
      if (req.method === 'GET' && asset) {
        if (req.headers.origin && req.headers.origin !== origin) { send(res, 403, { error: 'request_origin' }); return; }
        res.writeHead(200, { 'Content-Type': asset[0] + '; charset=utf-8' }); res.end(asset[1]); return;
      }
      const authority = webAuthority(req.headers, origin, token, siteOrigin, siteToken);
      if (!authority || authority === 'site' && !siteApi(req.method, req.url)) { send(res, 403, { error: 'session_required' }); return; }
      if (authority === 'site') { res.setHeader('Access-Control-Allow-Origin', siteOrigin!); res.setHeader('Vary', 'Origin'); }
      if (req.method === 'GET' && req.url === '/api/site-connection' && authority === 'local') {
        send(res, 200, siteOrigin ? { contract: webContract, siteOrigin, endpoint: origin, token: siteToken } : { siteOrigin: null }); return;
      }
      if (req.method === 'GET' && req.url === '/api/state') { send(res, 200, view()); return; }
      if (req.method === 'GET' && req.url === `/api/report/${job?.id}/html` && job?.htmlReport && !job.busy) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Disposition': 'attachment; filename="scanmux-report.html"', 'Content-Security-Policy': reportCsp });
        res.end(job.htmlReport); return;
      }
      if (req.method === 'GET' && req.url === `/api/report/${job?.id}` && job?.report && !job.busy) {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="scanmux-report.json"' });
        res.end(job.report); return;
      }
      if (req.method !== 'POST' || !['/api/prepare', '/api/run', '/api/cancel', '/api/shutdown'].includes(req.url ?? '')) { send(res, 404, { error: 'not_found' }); return; }
      if (closing || req.headers.origin !== (authority === 'site' ? siteOrigin : origin) || req.headers['content-type'] !== 'application/json') { send(res, 403, { error: 'request_origin' }); return; }
      const data = await body(req);
      if (closing) { send(res, 409, { error: 'server_closing' }); return; }
      if (req.url === '/api/shutdown') {
        if (Object.keys(data).length) { send(res, 400, { error: 'invalid_request' }); return; }
        if (replacing || job?.busy || job?.retained || job?.state === 'planned') { send(res, 409, { error: 'job_busy' }); return; }
        closing = true;
        send(res, 202, { state: 'closing' });
        void close().catch(() => { observationState = 'write_failed'; });
        return;
      }
      if (req.url === '/api/prepare') {
        if (Object.keys(data).length !== 1 || typeof data.url !== 'string') { send(res, 400, { error: 'invalid_request' }); return; }
        let url: string;
        try { url = githubUrl(data.url); } catch { send(res, 400, { error: 'public_github_url_required' }); return; }
        if (replacing || job?.busy || job?.retained) { send(res, 409, { error: 'job_busy' }); return; }
        replacing = true;
        try {
          if (job) await cleanup(job);
          if (closing) { send(res, 409, { error: 'server_closing' }); return; }
          const id = randomUUID();
          const next: Job = { id, state: 'preparing', phase: 'workspace', abort: new AbortController(), retained: false, busy: true, started: false, cleanup: new SourceCleanupOwner() };
          job = next;
          next.pending = withSourceCleanup(next.cleanup, () => prepare(next, url));
          send(res, 202, view());
        } catch (error) { if (job) fail(job, error); send(res, 409, { error: 'source_cleanup_failed' }); }
        finally { replacing = false; }
        return;
      }
      if (Object.keys(data).length !== 1 || typeof data.id !== 'string') { send(res, 400, { error: 'invalid_request' }); return; }
      if (!job || replacing || data.id !== job.id) { send(res, 409, { error: 'stale_job' }); return; }
      if (req.url === '/api/cancel') {
        cancel(job);
        send(res, 200, view()); return;
      }
      if (job.started) { send(res, 200, view()); return; }
      if (job.state !== 'planned' || job.busy || job.retained) { send(res, 409, { error: 'plan_required' }); return; }
      job.started = true; job.busy = true; job.state = 'running'; job.phase = 'static_scan';
      job.pending = withSourceCleanup(job.cleanup, () => run(job!));
      send(res, 202, view());
    } catch { if (!res.headersSent) send(res, 400, { error: 'invalid_request' }); else res.end(); }
  });
  server.requestTimeout = config.timeoutMs;
  server.headersTimeout = config.timeoutMs;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new SafeError('web_listen_failed');
  origin = `http://127.0.0.1:${address.port}`;
  return {
    url: `${origin}/#${token}`,
    closed: closed.promise,
    close,
  };
}
