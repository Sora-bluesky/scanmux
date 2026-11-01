import childProcess from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
import {randomUUID} from 'node:crypto';
import {performance} from 'node:perf_hooks';

const script='/assets/node_modules/@openai/codex-security/_bundled_plugin/scripts/workbench_db.py';
const schema='scanmux.sdk-initialization-observation/v2',wireSchema='scanmux.sdk-python-registration/v1';
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const plain=x=>x!==null&&typeof x==='object'&&Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,keys)=>plain(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const count=x=>Number.isSafeInteger(x)&&x>=0;
const unavailable=(helpers=0,closed=0)=>({schema,state:'unavailable',helperInvocations:helpers,closedInvocations:closed,sqliteFullObserved:false,otherSqliteErrorObserved:false,terminal:'none'});

export function parseSdkInitializationObservation(value,maximumHelpers){
  if(!count(maximumHelpers)||maximumHelpers===0||!exact(value,['schema','state','helperInvocations','closedInvocations','sqliteFullObserved','otherSqliteErrorObserved','terminal'])
    ||value.schema!==schema||!['observed','unavailable'].includes(value.state)||!count(value.helperInvocations)||value.helperInvocations>maximumHelpers
    ||!count(value.closedInvocations)||value.closedInvocations>value.helperInvocations||typeof value.sqliteFullObserved!=='boolean'||typeof value.otherSqliteErrorObserved!=='boolean'
    ||!['none','sqlite_full','other'].includes(value.terminal)||value.state==='observed'&&(value.helperInvocations!==1||value.closedInvocations!==1)
    ||value.state==='unavailable'&&(value.sqliteFullObserved||value.otherSqliteErrorObserved||value.terminal!=='none')
    ||value.terminal==='sqlite_full'&&(!value.sqliteFullObserved||value.otherSqliteErrorObserved))throw Error('sdk_initialization_observation_invalid');
  return structuredClone(value);
}

/** An observation is not accepted until the pipe and its actual child both close. */
export function createNativeInitializationReader({invocationId,pid,limits,budget={bytes:0,frames:0}}){
  let pending=Buffer.alloc(0),failed=false,ready=false,terminal,sequence=0,full=false,other=false,eof=false;
  const invalid=()=>{failed=true;pending=Buffer.alloc(0);};
  function record(bytes){
    if(failed)return;
    try{
      if(!bytes.length||bytes.length>limits.maxFrameBytes||++budget.frames>limits.maxFrames)return invalid();
      const row=JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes)),common=['schema','type','invocationId','pid','sequence'];
      const keys=row?.type==='ready'?[...common,'python','traceAbsent','profileAbsent']:row?.type==='error'?[...common,'kind']:[...common,'state','terminal'];
      if(!exact(row,keys)||row.schema!==wireSchema||!uuid.test(invocationId)||row.invocationId!==invocationId||!Number.isSafeInteger(pid)||pid<=0||row.pid!==pid||row.sequence!==++sequence||terminal!==undefined)return invalid();
      if(row.type==='ready'){
        if(ready||sequence!==1||JSON.stringify(row.python)!=='[3,11,2]'||row.traceAbsent!==true||row.profileAbsent!==true)return invalid();ready=true;
      }else if(row.type==='error'){
        if(!ready||!['full','other'].includes(row.kind))return invalid();if(row.kind==='full')full=true;else other=true;
      }else if(row.type==='end'){
        if(!ready||row.state!=='complete'||!['normal','sqlite_full','other'].includes(row.terminal)||row.terminal==='sqlite_full'&&(!full||other))return invalid();terminal=row.terminal;
      }else invalid();
    }catch{invalid();}
  }
  return{
    push(bytes){try{if(failed)return;if(eof||!Buffer.isBuffer(bytes))return invalid();budget.bytes+=bytes.length;if(!count(budget.bytes)||budget.bytes>limits.maxBytes)return invalid();pending=Buffer.concat([pending,bytes]);for(;;){const end=pending.indexOf(10);if(end<0)break;const line=pending.subarray(0,end);pending=pending.subarray(end+1);record(line);if(failed)return;}if(pending.length>limits.maxFrameBytes)invalid();}catch{invalid();}},
    end(){eof=true;},fail:invalid,
    finish(code,signal){const valid=!failed&&eof&&pending.length===0&&ready&&terminal!==undefined&&signal===null&&(terminal==='normal'?code===0:code===1);return{valid,sqliteFullObserved:valid&&full,otherSqliteErrorObserved:valid&&other,terminal:valid?(terminal==='normal'?'none':terminal):'none'};},
  };
}

export function isInitialRegistrationSpawn(command,args,options,cwd){
  try{
    const expected=['-I','-X','utf8','-B',script,'register-cli-scan','--repository','/handoff','--scan-dir','/work/outputs','--registration-json-stdin'];
    const env=options?.env;
    return command==='/usr/bin/python3'&&cwd==='/work'&&Array.isArray(args)&&args.length===expected.length&&args.every((arg,i)=>arg===expected[i])
      &&exact(options,['env','stdio','windowsHide','signal'])&&options.windowsHide===true&&Array.isArray(options.stdio)&&options.stdio.length===3&&options.stdio.every(x=>x==='pipe')
      &&typeof Reflect.apply(Object.getOwnPropertyDescriptor(AbortSignal.prototype,'aborted').get,options.signal,[])==='boolean'
      &&exact(env,['PATH','CODEX_SECURITY_STATE_DIR','TMPDIR','CODEX_SECURITY_GIT','PYTHONUTF8'])&&env.PATH==='/usr/local/bin:/usr/bin'&&env.CODEX_SECURITY_STATE_DIR==='/work/state'&&env.TMPDIR==='/tmp'&&env.CODEX_SECURITY_GIT==='/usr/bin/git'&&env.PYTHONUTF8==='1';
  }catch{return false;}
}

function bootstrap(ipc){
  return `import sys,runpy,os\nsys.argv.pop(0)\n_scanmux_scope={}\n_scanmux_finish=None\ntry:\n _scanmux_id=os.environ.pop('SCANMUX_NATIVE_INVOCATION')\n exec(compile(open('/verify/sdk-native-observer.py','rb').read(),'/verify/sdk-native-observer.py','exec'),_scanmux_scope)\n _scanmux_finish=_scanmux_scope['install'](_scanmux_id,${ipc.maxBytes},${ipc.maxFrameBytes},${ipc.maxFrames})\nexcept BaseException:\n pass\ntry:\n runpy.run_path(sys.argv[0],run_name='__main__')\nexcept BaseException as _scanmux_original:\n try:\n  if _scanmux_finish is not None: _scanmux_finish(_scanmux_original)\n except BaseException:\n  pass\n raise\nelse:\n try:\n  if _scanmux_finish is not None: _scanmux_finish(None)\n except BaseException:\n  pass\n`;
}

/** Importing is inert; only the verified isolated worker arms this boundary. */
export function observeSdkInitialization({ipc,signal,expiresAt}){
  const original=childProcess.spawn,entries=[],budget={bytes:0,frames:0};
  let armed=true,restored=false,attempted=false,failed=false,finishPromise;
  function wrapped(command,args,options){
    let candidate=false;
    try{candidate=armed&&Array.isArray(args)&&args.includes(script)&&args.includes('register-cli-scan');if(armed&&attempted&&!candidate)failed=true;}catch{failed=true;}
    if(!candidate)return Reflect.apply(original,this,arguments);
    attempted=true;
    let changedArgs,changedOptions,invocationId,attach=false;
    try{
      if(entries.length===0&&isInitialRegistrationSpawn(command,args,options,process.cwd())){
        invocationId=randomUUID();changedArgs=[...args.slice(0,4),'-c',bootstrap(ipc),...args.slice(4)];changedOptions={...options,env:{...options.env,SCANMUX_NATIVE_INVOCATION:invocationId},stdio:[...options.stdio,'pipe']};attach=true;
      }else failed=true;
    }catch{failed=true;}
    if(!attach)return Reflect.apply(original,this,arguments);
    let child;
    try{child=Reflect.apply(original,this,[command,changedArgs,changedOptions]);}catch(error){failed=true;throw error;}
    try{
      let resolve;const closed=new Promise(yes=>{resolve=yes;}),entry={closed,result:null};entries.push(entry);
      const reader=createNativeInitializationReader({invocationId,pid:child.pid,limits:ipc,budget});
      child.once('close',(code,endSignal)=>{try{entry.result=reader.finish(code,endSignal);}catch{failed=true;}finally{resolve();}});
      const pipe=child.stdio[3];pipe.on('data',bytes=>reader.push(bytes));pipe.once('end',()=>reader.end());pipe.once('error',()=>reader.fail());child.once('error',()=>reader.fail());
    }catch{failed=true;try{child.stdio?.[3]?.resume();}catch{}}
    return child;
  }
  function disarm(){
    if(restored)return;armed=false;
    try{if(childProcess.spawn===wrapped){childProcess.spawn=original;syncBuiltinESMExports();}else if(childProcess.spawn!==original)failed=true;}catch{failed=true;}
    restored=true;
  }
  try{
    if(process.platform!=='linux'||process.version!=='v24.22.1'||process.getuid()!==1000||![ipc.maxBytes,ipc.maxFrameBytes,ipc.maxFrames].every(x=>count(x)&&x>0))throw Error();
    childProcess.spawn=wrapped;syncBuiltinESMExports();
  }catch{attempted=true;failed=true;disarm();}
  async function finish(){
    if(finishPromise)return finishPromise;
    finishPromise=(async()=>{
      disarm();if(!attempted)return null;let timer,abort;
      try{
        if(entries.some(entry=>entry.result===null)){
          const remaining=Math.ceil(expiresAt-performance.now());
          if(signal.aborted||remaining<=0)failed=true;
          else await Promise.race([Promise.all(entries.map(entry=>entry.closed)),new Promise(resolve=>{abort=()=>{failed=true;resolve();};signal.addEventListener('abort',abort,{once:true});timer=setTimeout(abort,remaining);if(signal.aborted)abort();})]);
        }
        if(failed||entries.length!==1||!entries[0].result?.valid)return unavailable(entries.length,entries.filter(entry=>entry.result!==null).length);
        const observation=entries[0].result;
        return parseSdkInitializationObservation({schema,state:'observed',helperInvocations:1,closedInvocations:1,sqliteFullObserved:observation.sqliteFullObserved,otherSqliteErrorObserved:observation.otherSqliteErrorObserved,terminal:observation.terminal},ipc.maxFrames);
      }catch{return unavailable();}
      finally{try{clearTimeout(timer);if(abort)signal.removeEventListener('abort',abort);}catch{}}
    })();return finishPromise;
  }
  return{disarm,finish};
}
