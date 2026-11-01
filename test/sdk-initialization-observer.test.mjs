import test from 'node:test';
import assert from 'node:assert/strict';
import {createNativeInitializationReader, parseSdkInitializationObservation, isInitialRegistrationSpawn} from '../internal/sdk-initialization-observer.mjs';

const invocationId='12345678-1234-4234-8234-123456789abc',pid=21;
const limits={maxBytes:16384,maxFrameBytes:2048,maxFrames:16};
const receipt=()=>({schema:'scanmux.sdk-initialization-observation/v2',state:'observed',helperInvocations:1,closedInvocations:1,sqliteFullObserved:true,otherSqliteErrorObserved:false,terminal:'sqlite_full'});
const records=()=>[
  {type:'ready',python:[3,11,2],traceAbsent:true,profileAbsent:true},
  {type:'error',kind:'full'},
  {type:'end',state:'complete',terminal:'sqlite_full'},
].map((row,index)=>({schema:'scanmux.sdk-python-registration/v1',invocationId,pid,sequence:index+1,...row}));
const bytes=rows=>Buffer.from(rows.map(row=>JSON.stringify(row)+'\n').join(''));
function parse(rows,code=1,signal=null,edit){const reader=createNativeInitializationReader({invocationId,pid,limits});reader.push(bytes(rows));edit?.(reader);reader.end();return reader.finish(code,signal);}

test('the receipt requires one complete invocation and consistent terminal facts',()=>{
  assert.deepEqual(parseSdkInitializationObservation(receipt(),16),receipt());
  for(const edit of [x=>{x.schema='v1';},x=>{x.extra=true;},x=>{x.helperInvocations=2;},x=>{x.closedInvocations=0;},x=>{x.sqliteFullObserved=false;},x=>{x.otherSqliteErrorObserved=true;},x=>{x.state='unavailable';}]){const value=receipt();edit(value);assert.throws(()=>parseSdkInitializationObservation(value,16));}
  const unavailable={...receipt(),state:'unavailable',helperInvocations:0,closedInvocations:0,sqliteFullObserved:false,terminal:'none'};assert.deepEqual(parseSdkInitializationObservation(unavailable,16),unavailable);
});

test('the private pipe accepts only the bound complete native terminal',()=>{
  assert.deepEqual(parse(records()),{valid:true,sqliteFullObserved:true,otherSqliteErrorObserved:false,terminal:'sqlite_full'});
  const reader=createNativeInitializationReader({invocationId,pid,limits}),wire=bytes(records());for(const byte of wire)reader.push(Buffer.from([byte]));reader.end();assert.equal(reader.finish(1,null).terminal,'sqlite_full');
  const normal=[records()[0],{...records()[2],sequence:2,terminal:'normal'}];assert.deepEqual(parse(normal,0),{valid:true,sqliteFullObserved:false,otherSqliteErrorObserved:false,terminal:'none'});
  const caught=records();caught[2].terminal='normal';assert.equal(parse(caught,0).terminal,'none');
  const different=records();different[2].terminal='other';assert.equal(parse(different).terminal,'other');
  const mixed=records();mixed.splice(2,0,{...mixed[1],kind:'other'});mixed.forEach((row,i)=>{row.sequence=i+1;});assert.equal(parse(mixed).valid,false);mixed.at(-1).terminal='other';assert.equal(parse(mixed).otherSqliteErrorObserved,true);
});

for(const[name,edit,code,signal]of[
  ['foreign invocation',r=>{r[1].invocationId='foreign';}],['foreign pid',r=>{r[1].pid++;}],['duplicate sequence',r=>{r[1].sequence=1;}],
  ['missing ready',r=>{r.shift();}],['missing terminal',r=>{r.pop();}],['extra record',r=>{r.push({...r[2],sequence:4});}],
  ['extra field',r=>{r[1].message='ENOSPC';}],['different Python',r=>{r[0].python=[3,12,0];}],['preexisting trace',r=>{r[0].traceAbsent=false;}],['preexisting profiler',r=>{r[0].profileAbsent=false;}],
  ['observer failure',r=>{r[2].state='unavailable';}],['full with other terminal code',()=>{},2],['unexpected success exit',()=>{},0],['termination signal',()=>{},null,'SIGTERM'],
])test(`private native observation rejects ${name}`,()=>{const rows=records();edit(rows);assert.equal(parse(rows,code??1,signal??null).valid,false);});

test('malformed, incomplete, oversized and shared-budget pipes never assert positive facts',()=>{
  for(const malformed of [Buffer.from([0xff,10]),Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),bytes(records())]),Buffer.from('{bad}\n'),Buffer.concat([bytes(records()),Buffer.from('tail')]),Buffer.alloc(limits.maxBytes+1,65)]){
    const reader=createNativeInitializationReader({invocationId,pid,limits});reader.push(malformed);reader.end();assert.equal(reader.finish(1,null).sqliteFullObserved,false);
  }
  const reader=createNativeInitializationReader({invocationId,pid,limits});reader.push(bytes(records()));assert.equal(reader.finish(1,null).valid,false);
  const budget={bytes:limits.maxBytes,frames:0},shared=createNativeInitializationReader({invocationId,pid,limits,budget});shared.push(bytes(records()));shared.end();assert.equal(shared.finish(1,null).valid,false);
});

test('attachment matches the exact initial Python invocation and preserves the SDK signal',()=>{
  const command='/usr/bin/python3',args=['-I','-X','utf8','-B','/assets/node_modules/@openai/codex-security/_bundled_plugin/scripts/workbench_db.py','register-cli-scan','--repository','/handoff','--scan-dir','/work/outputs','--registration-json-stdin'];
  const options={env:{PATH:'/usr/local/bin:/usr/bin',CODEX_SECURITY_STATE_DIR:'/work/state',TMPDIR:'/tmp',CODEX_SECURITY_GIT:'/usr/bin/git',PYTHONUTF8:'1'},stdio:['pipe','pipe','pipe'],windowsHide:true,signal:AbortSignal.any([new AbortController().signal])};
  assert.equal(isInitialRegistrationSpawn(command,args,options,'/work'),true);
  for(const edit of [x=>{x.args.push('--archive-existing');},x=>{x.args[5]='database-info';},x=>{x.args[4]='/handoff/workbench_db.py';},x=>{x.options.env.EXTRA='value';},x=>{x.options.env.PATH='/handoff';},x=>{x.options.signal={aborted:false};},x=>{x.options.stdio[0]='ignore';},x=>{x.options.shell=true;},x=>{x.command='python3';},x=>{x.cwd='/handoff';}]){
    const value={command,args:[...args],options:{...options,env:{...options.env},stdio:[...options.stdio]},cwd:'/work'};edit(value);assert.equal(isInitialRegistrationSpawn(value.command,value.args,value.options,value.cwd),false);
  }
});
