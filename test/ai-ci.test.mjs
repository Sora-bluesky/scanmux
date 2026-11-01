import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { ciReceipt, evaluateCi, parseCiExpectation, parseCiReceipt, checkCiFiles, ciSummary } from '../src/ci.ts';
import { summarizeHistory } from '../src/history.ts';
import { defaults } from '../src/config.ts';
import { digest, hash } from '../src/safety.ts';
import { main } from '../src/cli.ts';
import { decide } from '../src/policy.ts';

const ciRun = '11111111-2222-3333-4444-555555555555';
function fixture() {
  const root = path.resolve('test'), files = [{ path:'source.ts', bytes:1, sha256:'a'.repeat(64) }], snapshotHash=digest(files), manifestSha256=digest(files);
  const report = { schema:'scanmux.report/v2', runId:'aaaaaaaa-1111-2222-3333-444444444444', startedAt:'2026-10-23T00:00:00Z', endedAt:'2026-10-23T00:00:01Z', gate:'PASS', exitCode:0, executionState:'completed', coverageState:'complete', integrityErrors:[],
    plan:{schema:'scanmux.plan/v2', root, repoId:hash(root), commit:'a'.repeat(40), policyHash:'b'.repeat(64), planHash:'c'.repeat(64), snapshotHash, files, required:['gitleaks','osv','codex-security','runtime-advisories'], blockers:[], exclusions:[], network:'openai-responses',
      ai:{schema:'scanmux.ai-plan/v1',source:{files:files.length,snapshotHash,manifestSha256},runtime:{imageDigest:'sha256:'+'d'.repeat(64)}}},
    engines:['gitleaks','osv','codex-security','runtime-advisories'].map(engine=>({engine,execution:'completed',coverage:'analyzed',errors:[],usage:{calls:0,cost:null,kind:'not_applicable',allowance:'unknown'}}))};
  report.engines[2].usage.calls=1;
  report.engines[2].aiExecution={schema:'scanmux.ai-execution/v1',classification:'provider',status:'completed',artifactsAccepted:true,originalCommit:report.plan.commit,snapshotHash,manifestSha256,sourcePreflight:'completed',
    submitInvocations:1,connectionAttempts:1,sendInvocations:1,tokens:{kind:'complete',observed:{inputTokens:3,outputTokens:2,totalTokens:5}},usageRecords:[{sequence:1,usage:{inputTokens:3,outputTokens:2,totalTokens:5}}],
    programs:['daybreak_blue'],cleanup:{closed:true,quiescent:true,containerAbsent:true},runtime:{imageDigest:report.plan.ai.runtime.imageDigest,boundaryVerified:true},coverage:{artifactsReviewed:1,exclusions:0,deferred:0,openQuestions:0,limitations:0,sha256:'e'.repeat(64)},
    artifacts:['scan-manifest.json','coverage.json','findings.json'].map(path=>({path,bytes:1,sha256:'f'.repeat(64)}))};
  report.plan.planHash=digest({...report.plan,planHash:''});
  return report;
}
const bytes=report=>Buffer.from(JSON.stringify(report,null,2)+'\n');
function expectation(report) {
  const {root,repoId,commit,policyHash,planHash,snapshotHash}=report.plan;
  return {schema:'scanmux.ci-expectation/v2',ciRun,jobs:[{id:'ai',analysis:'ai',targetRoot:root,repoId,commit,policyHash,planHash,snapshotHash}]};
}
const receipt=report=>ciReceipt({report,json:bytes(report).toString('utf8')},ciRun,'ai');
const evaluate=report=>evaluateCi(expectation(report),[receipt(report)],[bytes(report)]);

test('AI CI binds one exact saved report and shared completion; a provider-shaped control is not live service evidence',()=>{
  const report=fixture(),saved=bytes(report),tag=receipt(report),result=evaluate(report);
  assert.equal(tag.schema,'scanmux.ci-receipt/v2');assert.equal(tag.analysis,'ai');assert.equal(tag.reportHash,hash(saved));
  assert.equal(result.schema,'scanmux.ci-result/v2');assert.equal(result.gate,'PASS');assert.equal(result.exitCode,0);
  assert.deepEqual(result.jobs[0],{id:'ai',analysis:'ai',gate:'PASS',reasons:[],reportState:'verified',reportHash:hash(saved)});
  assert.equal(summarizeHistory([saved]).summary.runs[0].completion,'complete');
  report.untrusted='private-canary';const projected=evaluate(report);assert.equal(projected.gate,'PASS');assert.ok(!JSON.stringify(projected).includes('private-canary'));
  assert.ok(!JSON.stringify(projected).includes(report.plan.root));assert.deepEqual(Object.keys(projected).sort(),['schema','ciRun','gate','exitCode','jobs'].sort());
});

for(const programs of [['standard'],['daybreak_blue'],['daybreak_blue','standard']])test(`AI CI accepts effective ${programs} and preserves the requested program`,()=>{
  const report=fixture(),run=report.engines[2];report.plan.ai.accessProgram='daybreak_blue';report.plan.planHash=digest({...report.plan,planHash:''});
  run.accessProgramRequested='daybreak_blue';run.accessProgramEffective=programs.length===1?programs[0]:'unknown';run.aiExecution.programs=programs;
  const saved=bytes(report),result=evaluate(report),row=summarizeHistory([saved]).summary.runs[0];
  assert.equal(result.gate,'PASS');assert.equal(result.jobs[0].reportState,'verified');assert.deepEqual(result.jobs[0].reasons,[]);assert.equal(row.completion,'complete');
  const json=JSON.parse(saved);assert.equal(json.plan.ai.accessProgram,'daybreak_blue');assert.equal(json.engines[2].accessProgramRequested,'daybreak_blue');assert.equal(json.engines[2].accessProgramEffective,run.accessProgramEffective);assert.deepEqual(row.engines[2].ai.programs,programs);
  assert.equal(decide(report.plan,report.engines.map(engine=>({...engine,findings:[]}))).gate,'PASS');
});

for(const programs of [[],['unknown'],['daybreak_red'],['standard','unknown'],['standard','daybreak_red'],undefined])test(`AI CI refuses unverified effective ${programs}`,()=>{
  const report=fixture();report.engines[2].aiExecution.programs=programs;
  const row=summarizeHistory([bytes(report)]).summary.runs[0];
  assert.equal(evaluate(report).gate,'INCOMPLETE');assert.equal(row.completion,'incomplete');assert.ok(row.reasons.includes('ai_effective_program_unverified'));
});

test('CI text shows the effective standard program from the associated report without a Blue comparison or new saved fields',()=>{
  const report=fixture();report.engines[2].accessProgramRequested='daybreak_blue';report.engines[2].accessProgramEffective='standard';report.engines[2].aiExecution.programs=['standard'];
  const result=evaluate(report),text=ciSummary(result,[bytes(report)]);
  assert.match(text,/ai: PASS; reasons=none; effective program=standard\n/);assert.ok(!text.includes('Blue'));assert.ok(!text.includes('daybreak_blue'));
  assert.deepEqual(Object.keys(result.jobs[0]).sort(),['id','analysis','gate','reasons','reportState','reportHash'].sort());
  const missing=evaluateCi(expectation(report),[receipt(report)]);assert.match(ciSummary(missing),/effective program=unknown/);
  const unrelated=fixture();assert.match(ciSummary(result,[bytes(unrelated)]),/effective program=unknown/);
});

for (const schema of ['scanmux.ai-execution/v1', 'scanmux.ai-execution/v2']) test(`optional transport diagnostics preserve ${schema} completion and appear only for an associated CI report`, () => {
  const report = fixture(), ai = report.engines[2].aiExecution; ai.schema = schema;
  if (schema === 'scanmux.ai-execution/v2') {
    const limits = { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 33554432, workBytes: 16777216, shmBytes: 4194304 };
    report.plan.ai.schema = 'scanmux.ai-plan/v2'; report.plan.ai.workerResources = limits;
    ai.runtime.resources = { schema: 'scanmux.worker-resources/v1', state: 'verified', requested: limits,
      kernel: { cpuQuota: 100000, cpuPeriod: 100000, memoryMax: limits.memoryBytes, swapMax: 0, tmpBytes: limits.tmpBytes, workBytes: limits.workBytes, shmBytes: limits.shmBytes },
      events: { cpuThrottledPeriods: 0, oom: 0, oomKill: 0 }, terminal: { exitCode: 0, oomKilled: false }, exceeded: [] };
    report.plan.planHash = digest({ ...report.plan, planHash: '' });
  }
  const before = evaluate(report), completion = summarizeHistory([bytes(report)]).summary.runs[0].completion;
  assert.equal(before.gate, 'PASS'); assert.equal(completion, 'complete');
  ai.transportRequests = [{ sequence: 1, receivedBytes: 648, receivedMessages: 2, terminal: false, terminalKind: 'none', closeCode: 1006, sendOk: true, failureCode: 'response_limit' }];
  const result = evaluate(report), text = ciSummary(result, [bytes(report)]);
  assert.equal(result.gate, before.gate); assert.deepEqual(result.jobs[0].reasons, before.jobs[0].reasons);
  assert.equal(summarizeHistory([bytes(report)]).summary.runs[0].completion, completion);
  assert.match(text, /\n  AI transport diagnostic #1: response_limit\n/);
  assert.ok(!ciSummary(result).includes('AI transport diagnostic'));
  assert.ok(!ciSummary(result, [bytes(fixture())]).includes('AI transport diagnostic'));
  ai.transportRequests = [{ sequence: 1, failureCode: 'private-canary\nforged: PASS' }, { sequence: 'private-canary', failureCode: 'response_limit' }, null];
  assert.ok(!ciSummary(evaluate(report), [bytes(report)]).includes('private-canary'));
  assert.equal(evaluate(report).gate, before.gate);
});

for(const [name,change,reason] of [
  ['synthetic',ai=>{ai.classification='synthetic';},'ai_synthetic_evidence'],
  ['unknown usage',ai=>{ai.tokens={kind:'unknown',observed:null};ai.usageRecords=[];},'ai_usage_incomplete'],
  ['insufficient scope',ai=>{ai.coverage.artifactsReviewed=0;},'ai_scope_incomplete'],
  ['unverified interruption',ai=>{ai.status='acceptance_unknown';ai.cleanup.closed=false;},'ai_cleanup_unverified'],
])test(`AI CI still refuses standard with ${name}`,()=>{
  const report=fixture();report.engines[2].aiExecution.programs=['standard'];change(report.engines[2].aiExecution);
  assert.equal(evaluate(report).gate,'INCOMPLETE');const row=summarizeHistory([bytes(report)]).summary.runs[0];assert.ok(row.reasons.includes(reason));assert.ok(!row.reasons.includes('ai_effective_program_unverified'));
});

test('every AI acceptance, program, usage, cleanup, source, runtime and scope sibling refuses CI PASS',()=>{
  const cases=[r=>{r.engines[2].aiExecution.classification='synthetic';},r=>{r.engines[2].aiExecution.tokens.kind='partial';},r=>{r.engines[2].aiExecution.artifactsAccepted=false;},r=>{delete r.engines[2].aiExecution;},r=>{r.engines[2].errors=['private-canary'];}];
  for(const status of ['not_started','failed','canceled','budget_exceeded','acceptance_unknown',undefined])cases.push(r=>{r.engines[2].aiExecution.status=status;});
  for(const programs of [[],['unknown'],['daybreak_red'],['daybreak_blue','unknown'],['daybreak_blue','daybreak_red'],undefined])cases.push(r=>{r.engines[2].aiExecution.programs=programs;});
  for(const field of ['closed','quiescent','containerAbsent'])for(const value of [false,undefined])cases.push(r=>{r.engines[2].aiExecution.cleanup[field]=value;});
  for(const field of ['exclusions','deferred','openQuestions','limitations'])for(const value of [1,undefined])cases.push(r=>{r.engines[2].aiExecution.coverage[field]=value;});
  for(const field of ['coverage','cleanup','artifacts','sourcePreflight','runtime','manifestSha256'])cases.push(r=>{delete r.engines[2].aiExecution[field];});
  cases.push(r=>{r.engines[2].aiExecution.coverage.artifactsReviewed=2;},r=>{r.engines[2].aiExecution.originalCommit='f'.repeat(40);},r=>{r.engines[2].aiExecution.runtime.boundaryVerified=false;});
  for(const mutate of cases){const report=fixture();mutate(report);const before=bytes(report),result=evaluate(report);assert.equal(result.gate,'INCOMPLETE');assert.ok(result.jobs[0].reasons.includes('ci_ai_analysis_incomplete'));assert.deepEqual(bytes(report),before);assert.ok(!JSON.stringify(result).includes('private-canary'));}
  const unknown=fixture();unknown.engines[2].aiExecution.tokens={kind:'unknown',observed:null};unknown.engines[2].aiExecution.usageRecords=[];assert.equal(evaluate(unknown).gate,'INCOMPLETE');
});

test('CI preserves every recorded gate and stronger failures when AI evidence is incomplete',()=>{
  const expected=['INCOMPLETE','INCOMPLETE','INCOMPLETE','FAIL','ERROR'];
  for(const [index,gate] of ['PASS','REVIEW','INCOMPLETE','FAIL','ERROR'].entries()){
    const report=fixture();report.gate=gate;report.exitCode={PASS:0,REVIEW:2,INCOMPLETE:3,FAIL:1,ERROR:4}[gate];report.engines[2].aiExecution.classification='synthetic';
    assert.equal(evaluate(report).gate,expected[index]);
  }
  const report=fixture();report.engines[2].execution='failed';assert.equal(evaluate(report).gate,'ERROR');
});

test('required AI report, receipt, job and every engine omission or skip remain incomplete',()=>{
  const report=fixture(),expected=expectation(report),tag=receipt(report);
  assert.equal(evaluateCi(expected,[]).gate,'INCOMPLETE');
  const missing=evaluateCi(expected,[tag]);assert.equal(missing.gate,'INCOMPLETE');assert.equal(missing.jobs[0].reportState,'missing');assert.equal(missing.jobs[0].reportHash,null);assert.ok(missing.jobs[0].reasons.includes('required_ai_report_missing'));
  for(let i=0;i<4;i++){
    const input=fixture();input.engines.splice(i,1);const partialTag={...tag,engines:input.engines.map(({engine,execution,coverage})=>({engine,execution,coverage})),reportHash:hash(bytes(input))};
    assert.equal(evaluateCi(expected,[partialTag],[bytes(input)]).gate,'INCOMPLETE');
    for(const coverage of ['partial','skipped','unsupported']){const input=fixture();input.engines[i].coverage=coverage;assert.equal(evaluate(input).gate,'INCOMPLETE');}
    for(const execution of ['not_started','cancelled','budget_exceeded']){const input=fixture();input.engines[i].execution=execution;assert.equal(evaluate(input).gate,'INCOMPLETE');}
  }
});

test('AI receipt/report identity mismatches, changed bytes, duplicate and unused report inputs cannot pass',()=>{
  const report=fixture(),saved=bytes(report),expected=expectation(report),tag=receipt(report);
  for(const key of ['repoId','commit','policyHash','planHash','snapshotHash','ciRun','reportRunId']){
    const changed={...tag,[key]:tag[key].replace(/[a-f0-9]/g,'f')};const result=evaluateCi(expected,[changed],[saved]);assert.equal(result.gate,'ERROR',key);assert.equal(result.jobs[0].reportState,'missing');
  }
  for(const field of ['gate','executionState','coverageState']){
    const value={gate:'ERROR',executionState:'failed',coverageState:'incomplete'}[field],changed={...tag,[field]:value};assert.equal(evaluateCi(expected,[changed],[saved]).gate,'ERROR');
  }
  const changedEngine=structuredClone(tag);changedEngine.engines[0].coverage='partial';assert.equal(evaluateCi(expected,[changedEngine],[saved]).gate,'ERROR');
  assert.throws(()=>evaluateCi(expected,[tag],[Buffer.from(JSON.stringify(report))]),/ci_report_unassociated/);
  assert.throws(()=>evaluateCi(expected,[tag],[saved,saved]),/invalid_ci_report/);
  const extra=fixture();extra.runId='bbbbbbbb-1111-2222-3333-444444444444';assert.throws(()=>evaluateCi(expected,[tag],[saved,bytes(extra)]),/ci_report_unassociated/);
  const reused=structuredClone(tag);reused.jobId='other';const repeated={...expected,jobs:[...expected.jobs,{...expected.jobs[0],id:'other'}]};assert.throws(()=>evaluateCi(repeated,[tag,reused],[saved]));
});

test('v1 compatibility, explicit v2 modes and mixed offline/AI jobs never downgrade AI to receipt-only',()=>{
  const report=fixture(),expected=expectation(report),tag=receipt(report),v1={...expected,schema:'scanmux.ci-expectation/v1',jobs:expected.jobs.map(({analysis,...job})=>job)};
  assert.throws(()=>evaluateCi(v1,[tag]),/invalid_ci_manifest/);assert.throws(()=>evaluateCi(v1,[],[bytes(report)]),/invalid_ci_manifest/);
  const offline=fixture();delete offline.plan.ai;offline.plan.network='offline';delete offline.engines[2].aiExecution;offline.engines[2].usage.calls=0;
  const oldTag=receipt(offline);assert.equal(oldTag.schema,'scanmux.ci-receipt/v1');assert.equal(evaluateCi(v1,[oldTag]).schema,'scanmux.ci-result/v1');assert.equal(evaluateCi(v1,[oldTag]).gate,'PASS');
  assert.equal(evaluateCi(expected,[oldTag]).gate,'ERROR');
  const offlineExpected={...expected,jobs:expected.jobs.map(job=>({...job,analysis:'offline'}))};assert.throws(()=>evaluateCi(offlineExpected,[tag],[bytes(report)]),/ci_report_unassociated/);
  assert.equal(evaluateCi(offlineExpected,[oldTag]).gate,'PASS');
  const modeLie={...tag,reportHash:hash(bytes(offline))};assert.equal(evaluateCi(expected,[modeLie],[bytes(offline)]).gate,'ERROR');
  const offJob={...offlineExpected.jobs[0],id:'offline'},offReceipt={...oldTag,jobId:'offline',reportRunId:'bbbbbbbb-1111-2222-3333-444444444444'};
  const mixed={...expected,jobs:[offJob,...expected.jobs]},result=evaluateCi(mixed,[tag,offReceipt],[bytes(report)]);assert.equal(result.gate,'PASS');assert.deepEqual(result.jobs.map(job=>job.analysis),['offline','ai']);
});

test('v2 CI schemas reject unknown keys, missing modes, invalid values and malformed saved usage',()=>{
  const report=fixture(),expected=expectation(report),tag=receipt(report);
  for(const value of [undefined,null,'synthetic','standard',true,{}]){
    const input=structuredClone(expected);input.jobs[0].analysis=value;assert.throws(()=>parseCiExpectation(input));assert.throws(()=>parseCiReceipt({...tag,analysis:value}));
  }
  assert.throws(()=>parseCiExpectation({...expected,extra:true}));assert.throws(()=>parseCiReceipt({...tag,completion:'complete'}));
  for(const field of ['tokens','usageRecords']){const input=fixture();input.engines[2].aiExecution[field]=null;assert.throws(()=>evaluate(input));}
  assert.throws(()=>evaluateCi(expected,[tag],[Buffer.from([0xc0,0xaf])]));
});

test('report file admission includes reports in aggregate byte, duplicate path and all-target boundaries',async()=>{
  const folder=await fs.mkdtemp(path.join(tmpdir(),'scanmux-ai-ci-'));
  test.after(() => removeTempDir(folder));
  const target=path.join(folder,'target');await fs.mkdir(target);
  const report=fixture();report.plan.root=target;report.plan.repoId=hash(target);const expected=expectation(report),tag=receipt(report);
  const expectationPath=path.join(folder,'expected.json'),receiptPath=path.join(folder,'receipt.json'),reportPath=path.join(folder,'report.json');
  const inputs=[JSON.stringify(expected),JSON.stringify(tag),bytes(report)];for(const [i,file]of[expectationPath,receiptPath,reportPath].entries())await fs.writeFile(file,inputs[i]);
  await assert.rejects(checkCiFiles(expectationPath,[receiptPath],undefined,{...defaults,maxOutputBytes:inputs.reduce((n,value)=>n+Buffer.byteLength(value),0)-1},[reportPath]),/file_limit/);
  await assert.rejects(checkCiFiles(expectationPath,[receiptPath],undefined,defaults,[receiptPath]),/invalid_ci_manifest/);
  const inside=path.join(target,'report.json');await fs.writeFile(inside,inputs[2]);await assert.rejects(checkCiFiles(expectationPath,[receiptPath],undefined,defaults,[inside]),/ci_input_inside_target/);
  await fs.writeFile(reportPath,Buffer.from([0xc0,0xaf]));await assert.rejects(checkCiFiles(expectationPath,[receiptPath],undefined,defaults,[reportPath]));
});

test('CI report options are refused on every sibling and unpaired AI CI tags stop before configuration',async()=>{
  const saved=process.stderr.write,errors=[];process.stderr.write=chunk=>{errors.push(String(chunk));return true;};
  try{
    for(const command of ['doctor','plan','scan','ai-plan','ai-scan','scan-list','plan-list','resume','serve','runner-check','history','dispositions','policy-check']){
      errors.length=0;const args=[command,...(['doctor','serve','runner-check'].includes(command)?[]:['synthetic-target']),'--config','missing-config','--ci-report','missing-report',...(command==='ai-scan'?['--accept-plan','0'.repeat(64)]:[])];
      assert.equal(await main(args),4);assert.equal(JSON.parse(errors.join('')).error,'invalid_command');
    }
    errors.length=0;assert.equal(await main(['ai-scan','synthetic-target','--config','missing-config','--accept-plan','0'.repeat(64),'--ci-run',ciRun]),4);assert.equal(JSON.parse(errors.join('')).error,'invalid_ci_manifest');
  }finally{process.stderr.write=saved;}
});

test('a saved AI plan carrying its destination disclosure passes the CI receipt, CI evaluation and history readers',()=>{
  const report=fixture();
  report.plan.destinations={schema:'scanmux.destinations/v1',rule:'send_only_to_validated_software',ruleMet:false,destinations:[
    {side:'local',component:'linux-image',sha256:'d'.repeat(64),level:'digest_pinned_only'},{side:'local',component:'docker',sha256:null,level:'unidentified'},
    {side:'provider',component:'openai-responses',attestation:'unattestable',reason:'provider_offers_no_software_attestation'}]};
  report.plan.planHash=digest({...report.plan,planHash:''});
  const saved=bytes(report),tag=receipt(report),result=evaluate(report);
  assert.equal(tag.schema,'scanmux.ci-receipt/v2');assert.equal(tag.planHash,report.plan.planHash);
  assert.equal(result.gate,'PASS');assert.deepEqual(result.jobs[0].reasons,[]);assert.equal(result.jobs[0].reportState,'verified');
  assert.equal(summarizeHistory([saved]).summary.runs[0].completion,'complete');
});
