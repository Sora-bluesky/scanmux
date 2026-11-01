using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

// Trusted resource/lifetime owner for one fixed ScanMux worker, never a target launcher.
public static class ScanMuxWindowsJobOwner {
 const string Version="1.1.0";
 const uint KillOnClose=0x2000, JobMemory=0x200, CpuHard=5;
 const uint CreateSuspended=4, UnicodeEnvironment=0x400, ExtendedStartup=0x80000, NoWindow=0x08000000;
 const uint NewProcess=6, Signaled=0, StillActive=259, ForcedExit=0xe1000001;
 static readonly UTF8Encoding Utf8=new UTF8Encoding(false,true);
 static readonly JavaScriptSerializer Json=new JavaScriptSerializer { MaxJsonLength=65536 };
 static readonly Stopwatch Clock=Stopwatch.StartNew();
 static volatile bool Cancelled;
 static double ClosingAt=-1;
 static long CleanupMs;
 static RetainedContext Storage;
 static string CopyBudgetArgument;
 sealed class OwnerError:Exception { public readonly string operation;public readonly uint code;public OwnerError(string op,uint error){operation=op;code=error;} }
 sealed class Generation {
  public IntPtr handle; public uint pid; public string created; public bool signaled; public uint? exitCode;
  public object Record(){return Obj("pid",pid,"creationFileTime",created,"memberVerified",true,"signaled",signaled,"exitCode",exitCode);}
 }
 sealed class Phase {
  public string name,reason="failed"; public bool configured,member,coverage,monotonic=true;
  public uint cpuFlags,cpuRate,flags,total,maximum,samples; public ulong memory;
  public double start,end; public uint rootPid;public string rootCreated;
  public OwnerError error; public List<Generation> generations=new List<Generation>();
  public object Record(){var rows=new List<object>();foreach(var g in generations)rows.Add(g.Record());return Obj("phase",name,"reason",reason,"configured",configured,"memberBeforeResume",member,
   "cpuFlags",cpuFlags,"cpuRate",cpuRate,"memoryBytes",memory,"limitFlags",flags,
   "root",rootPid==0?null:Obj("pid",rootPid,"creationFileTime",rootCreated),"processes",rows,
   "totalProcesses",total,"maximumTotalProcesses",maximum,"accountingSamples",samples,"accountingMonotonic",monotonic,"coverageComplete",coverage,
   "startedMs",start,"endedMs",end,"closingStartedMs",ClosingAt<0?null:(object)ClosingAt,
   "error",error==null?null:Obj("operation",error.operation,"win32",error.code));}
 }
 static Dictionary<string,object> Obj(params object[] pairs){var result=new Dictionary<string,object>();for(int i=0;i<pairs.Length;i+=2)result.Add((string)pairs[i],pairs[i+1]);return result;}
 static Dictionary<string,object> Map(object input){var map=input as Dictionary<string,object>;Check(map!=null,"descriptor");return map;}
 static void Keys(Dictionary<string,object> value,params string[] keys){Check(value.Count==keys.Length,"descriptor");foreach(string key in keys)Check(value.ContainsKey(key),"descriptor");}
 static void Check(bool value,string operation){if(!value)throw new OwnerError(operation,0);}
 static void Native(bool value,string operation){int error=Marshal.GetLastWin32Error();if(!value)throw new OwnerError(operation,unchecked((uint)error));}
 static string Text(object value){Check(value is string,"descriptor");return (string)value;}
 static long Integer(object value,long min,long max){Check(value is int || value is long,"descriptor");long n=Convert.ToInt64(value,CultureInfo.InvariantCulture);Check(n>=min && n<=max,"descriptor");return n;}
 static double Now(){return Clock.Elapsed.TotalMilliseconds;}
 static void Closing(){if(ClosingAt<0)ClosingAt=Now();}
 static bool Expired(){return ClosingAt>=0 && Now()>=ClosingAt+CleanupMs;}
 static string Full(string value){Check(value.Length>=3 && Char.IsLetter(value[0]) && value[1]==':' && (value[2]=='\\' || value[2]=='/') && value.Substring(2).IndexOf(':')<0 && value.IndexOfAny(new char[]{'\r','\n','\0'})<0,"descriptor");return Path.GetFullPath(value);}
 static string Quote(string value){Check(value.IndexOfAny(new char[]{'\r','\n','\0'})<0,"descriptor");var b=new StringBuilder("\"");int slashes=0;foreach(char c in value){if(c=='\\'){slashes++;continue;}if(c=='"')b.Append('\\',slashes*2+1);else b.Append('\\',slashes);slashes=0;b.Append(c);}b.Append('\\',slashes*2).Append('"');return b.ToString();}
 static byte[] Read(string path,int maximum){var file=new FileInfo(path);Check(file.Exists && (file.Attributes&FileAttributes.ReparsePoint)==0 && file.Length<=maximum,"descriptor");using(var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){var data=new byte[maximum+1];int count=0,read;while(count<data.Length && (read=stream.Read(data,count,data.Length-count))>0)count+=read;Check(count<=maximum,"descriptor");var exact=new byte[count];Buffer.BlockCopy(data,0,exact,0,count);return exact;}}
 static string Hash(byte[] bytes){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
 static string HashFile(string path,long bytes){var info=new FileInfo(path);Check(info.Exists && (info.Attributes&FileAttributes.ReparsePoint)==0 && info.Length==bytes,"hash");long stamp=info.LastWriteTimeUtc.Ticks;using(var sha=SHA256.Create())using(var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){byte[] buffer=new byte[65536];long total=0;int read;while((read=input.Read(buffer,0,buffer.Length))>0){total+=read;Check(total<=bytes,"hash");sha.TransformBlock(buffer,0,read,buffer,0);}sha.TransformFinalBlock(new byte[0],0,0);info.Refresh();Check(total==bytes && info.Length==bytes && info.LastWriteTimeUtc.Ticks==stamp,"hash");return BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();}}
 static void IdentityFile(string path,Dictionary<string,object> identity){Keys(identity,"bytes","sha256");Check(HashFile(path,Integer(identity["bytes"],1,9007199254740991))==Text(identity["sha256"]),"hash");}
 static void Save(string path,object result,int maximum){byte[] bytes=Utf8.GetBytes(Json.Serialize(result)+"\n");Check(bytes.Length<=maximum,"save");using(var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read,4096,FileOptions.WriteThrough)){file.Write(bytes,0,bytes.Length);file.Flush(true);}}
 static void SaveOwned(string file,object result,int maximum){
  if(Storage==null){Save(file,result,maximum);return;}
  byte[] bytes=Utf8.GetBytes(Json.Serialize(result)+"\n");Check(bytes.Length<=maximum,"save");int slot=Path.GetFileName(file)=="host-job-primary.json"?6:Path.GetFileName(file)=="host-job-native.json"?8:-1;Check(slot>=0,"save");
  using(var store=new RetainedStore(Storage,false)){var committed=store.WriteBatch(new[]{new RetainedPart(slot,bytes)},false);Check(committed.result=="committed","save");}
 }
 static byte[] ReadInput(int maximum){var buffer=new byte[maximum+1];int used=0,read;var input=Console.OpenStandardInput();while(used<buffer.Length&&(read=input.Read(buffer,used,buffer.Length-used))>0)used+=read;Check(used>0&&used<=maximum,"descriptor");var bytes=new byte[used];Buffer.BlockCopy(buffer,0,bytes,0,used);return bytes;}
 static RetainedContext RetainedIntent(string directory,string expected,byte[] raw){
  Check(Hash(raw)==expected,"hash");var intent=Map(Json.DeserializeObject(Utf8.GetString(raw)));
  Keys(intent,"schema","mode","jobId","root","directory","comparison","rootIdentity","host","hostSource","offline","offlineSource","application","assets","nodeIdentity","ownerIdentity","maxProcesses","storage");
  Check(Text(intent["schema"])=="scanmux.host-job-intent/v2"&&Text(intent["mode"])=="scan"&&Full(Text(intent["directory"]))==directory,"descriptor");
  Guid id;Check(Guid.TryParseExact(Text(intent["jobId"]),"D",out id)&&id.ToString()==Text(intent["jobId"]),"descriptor");
  var host=Map(intent["host"]);Keys(host,"schema","name","scope","offlineProfile","owner","node","limits","retained");Check(Text(host["schema"])=="scanmux.host-job-profile/v2"&&Text(host["scope"])=="windows-offline-local","descriptor");
  var requested=Map(host["retained"]);var geometry=Map(intent["storage"]);Keys(requested,"allocatedBytes");Keys(geometry,"fileSystem","clusterBytes","allocatedBytes");
  long budget=Integer(requested["allocatedBytes"],1,9007199254740991),cluster=Integer(geometry["clusterBytes"],1,9007199254740991);Check(Text(geometry["fileSystem"])=="NTFS"&&Integer(geometry["allocatedBytes"],1,9007199254740991)==budget&&budget%cluster==0,"descriptor");
  var owner=Map(host["owner"]);var node=Map(host["node"]);Keys(owner,"path","sha256","version");Keys(node,"path","sha256","version");Check(Text(owner["version"])==Version&&Full(Text(owner["path"]))==Full(System.Reflection.Assembly.GetExecutingAssembly().Location),"descriptor");
  var rootIdentity=Map(intent["rootIdentity"]);Keys(rootIdentity,"device","inode","modifiedNs");var actualRoot=RetainedStore.DirectoryIdentity(Full(Text(intent["root"])));foreach(string key in new[]{"device","inode","modifiedNs"})Check(Text(rootIdentity[key])==Text(actualRoot[key]),"identity");
  var profileSource=Map(intent["hostSource"]);Keys(profileSource,"path","identity");IdentityFile(Full(Text(profileSource["path"])),Map(profileSource["identity"]));IdentityFile(Full(Text(host["offlineProfile"])),Map(intent["offlineSource"]));
  IdentityFile(Full(Text(owner["path"])),Map(intent["ownerIdentity"]));IdentityFile(Full(Text(node["path"])),Map(intent["nodeIdentity"]));Check(Text(Map(intent["ownerIdentity"])["sha256"])==Text(owner["sha256"])&&Text(Map(intent["nodeIdentity"])["sha256"])==Text(node["sha256"]),"hash");
  int maximum=checked((int)Integer(Map(Map(intent["offline"])["scan"])["maxOutputBytes"],1,int.MaxValue));var assets=new List<RetainedAsset>();var seen=new HashSet<string>(StringComparer.Ordinal);string application=Full(Text(intent["application"]));bool worker=false;
  foreach(object entry in (object[])intent["assets"]){var asset=Map(entry);Keys(asset,"path","bytes","sha256");string relative=Text(asset["path"]);Check(!Path.IsPathRooted(relative)&&relative.IndexOfAny(new char[]{'\\',':','\0','\r','\n'})<0&&Array.IndexOf(relative.Split('/'),"..")<0&&seen.Add(relative),"descriptor");string file=Full(Path.Combine(application,relative.Replace('/',Path.DirectorySeparatorChar)));Check(file.StartsWith(application+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase),"descriptor");long bytes=Integer(asset["bytes"],1,9007199254740991);string sha=Text(asset["sha256"]);Check(HashFile(file,bytes)==sha,"hash");assets.Add(new RetainedAsset(relative,bytes,sha));if(relative=="internal/windows-job-worker.mjs")worker=true;}
  Check(worker&&assets.Count>0,"descriptor");return new RetainedContext{directory=directory,jobId=id.ToString(),intentSha256=expected,maximum=maximum,allocatedBytes=budget,clusterBytes=cluster,assets=assets.ToArray()};
 }
 static int RetainedOperation(string[] args){
  Check(Environment.Is64BitProcess&&args.Length>=2,"descriptor");string directory=Full(args[1]);Check(Directory.Exists(directory),"descriptor");
  if(args[0]=="--retained-probe"){Check(args.Length==2,"descriptor");Console.WriteLine(Json.Serialize(RetainedStore.Probe(directory)));return 0;}
  Check(args.Length==3&&(args[0]=="--retained-init"||args[0]=="--retained-write"||args[0]=="--retained-inspect"),"descriptor");
  bool initialize=args[0]=="--retained-init";byte[] raw=initialize?ReadInput(65536):Read(Path.Combine(directory,"host-job-intent.json"),65536);var context=RetainedIntent(directory,args[2],raw);
  using(var store=new RetainedStore(context,initialize)){
   if(args[0]=="--retained-inspect"){Console.WriteLine(Json.Serialize(Obj("schema","scanmux.retained-inspection/v1","jobId",context.jobId,"intentSha256",context.intentSha256,"snapshot",store.Inspect())));return 0;}
   RetainedPart[] parts=initialize?new[]{new RetainedPart(0,raw)}:RetainedStore.Decode(Console.OpenStandardInput(),context.maximum);
   Console.WriteLine(Json.Serialize(store.WriteBatch(parts,initialize)));return 0;
  }
 }
 static string Created(IntPtr process){long c,e,k,u;Native(GetProcessTimes(process,out c,out e,out k,out u),"identity");Check(c>0,"identity");return c.ToString(CultureInfo.InvariantCulture);}
 static bool Member(IntPtr process,IntPtr job){bool member;Native(IsProcessInJob(process,job,out member),"membership");return member;}
 static string CleanEnvironment(){string[] names={"SystemRoot","WINDIR","HOME","USERPROFILE","TMP","TEMP","TMPDIR","XDG_CONFIG_HOME","XDG_CACHE_HOME","LOCALAPPDATA","APPDATA","LANG","LC_ALL","NO_COLOR","GIT_CONFIG_NOSYSTEM","GIT_CONFIG_GLOBAL","GIT_NO_LAZY_FETCH","GIT_NO_REPLACE_OBJECTS","GIT_OPTIONAL_LOCKS","GIT_TERMINAL_PROMPT","GIT_ATTR_NOSYSTEM"};Array.Sort(names,StringComparer.OrdinalIgnoreCase);var block=new StringBuilder();foreach(string name in names){string value=Environment.GetEnvironmentVariable(name);if(value!=null)block.Append(name).Append('=').Append(value).Append('\0');}return block.Append('\0').ToString();}
 static void WatchParent(){var reader=new Thread(delegate(){try{var input=Console.OpenStandardInput();int length=0;var line=new StringBuilder();for(;;){int value=input.ReadByte();if(value<0)break;if(value==10){Check(line.ToString()=="CANCEL","descriptor");Cancelled=true;line.Length=0;length=0;}else{Check(++length<=16 && value>=32 && value<=126,"descriptor");line.Append((char)value);}}}catch{}finally{TerminateProcess(GetCurrentProcess(),ForcedExit);}});reader.IsBackground=true;reader.Start();}
 static void Set<T>(IntPtr job,int kind,T value){int size=Marshal.SizeOf(typeof(T));IntPtr data=Marshal.AllocHGlobal(size);try{Marshal.StructureToPtr(value,data,false);Native(SetInformationJobObject(job,kind,data,(uint)size),"set_limits");}finally{Marshal.FreeHGlobal(data);}}
 static T Query<T>(IntPtr job,int kind,string op){int size=Marshal.SizeOf(typeof(T));IntPtr data=Marshal.AllocHGlobal(size);try{uint returned;Native(QueryInformationJobObject(job,kind,data,(uint)size,out returned),op);return (T)Marshal.PtrToStructure(data,typeof(T));}finally{Marshal.FreeHGlobal(data);}}
 static ProcessInformation Create(IntPtr job,string node,string worker,string directory,string phase,string intentSha){
  var startup=new StartupInfoEx();startup.startup.cb=(uint)Marshal.SizeOf(typeof(StartupInfoEx));IntPtr attribute=IntPtr.Zero,jobArray=IntPtr.Zero,environment=IntPtr.Zero;var process=new ProcessInformation();bool initialized=false;
  try{IntPtr size=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);Check(size.ToInt64()>0,"attributes");attribute=Marshal.AllocHGlobal(size);Native(InitializeProcThreadAttributeList(attribute,1,0,ref size),"attributes");initialized=true;jobArray=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobArray,job);Native(UpdateProcThreadAttribute(attribute,0,new IntPtr(0x2000D),jobArray,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero),"attributes");startup.attributes=attribute;environment=Marshal.StringToHGlobalUni(CleanEnvironment());
   string command=Quote(node)+" "+Quote(worker)+" "+phase+" "+Quote(directory)+" "+intentSha+(phase=="run"&&CopyBudgetArgument!=null?" "+CopyBudgetArgument:"");
   Native(CreateProcess(node,new StringBuilder(command),IntPtr.Zero,IntPtr.Zero,false,CreateSuspended|ExtendedStartup|UnicodeEnvironment|NoWindow,environment,directory,ref startup,out process),"create_process");return process;
  }finally{if(initialized)DeleteProcThreadAttributeList(attribute);if(attribute!=IntPtr.Zero)Marshal.FreeHGlobal(attribute);if(jobArray!=IntPtr.Zero)Marshal.FreeHGlobal(jobArray);if(environment!=IntPtr.Zero)Marshal.FreeHGlobal(environment);}
 }
 static void Capture(Phase phase,IntPtr job,uint pid,int capacity){
  foreach(var known in phase.generations)if(known.pid==pid && !known.signaled)return;
  IntPtr handle=OpenProcess(0x100000|0x1000,false,pid);Native(handle!=IntPtr.Zero,"capture");
  try{string created=Created(handle);foreach(var known in phase.generations)if(known.pid==pid && known.created==created)return;Check(Member(handle,job),"capture");Check(phase.generations.Count<capacity,"capacity");phase.generations.Add(new Generation{handle=handle,pid=pid,created=created});handle=IntPtr.Zero;}
  finally{if(handle!=IntPtr.Zero)CloseHandle(handle);}
 }
 static void Discover(Phase phase,IntPtr job,IntPtr port,int capacity){
  uint message;UIntPtr key;IntPtr payload;
  while(GetQueuedCompletionStatus(port,out message,out key,out payload,0)){Check(key.ToUInt64()==unchecked((ulong)job.ToInt64()),"identity");if(message==NewProcess){ulong pid=unchecked((ulong)payload.ToInt64());Check(pid>0 && pid<=uint.MaxValue,"identity");Capture(phase,job,(uint)pid,capacity);}}
  int error=Marshal.GetLastWin32Error();Check(error==258,"capture");
  int size=checked(8+IntPtr.Size*capacity);IntPtr list=Marshal.AllocHGlobal(size);
  try{uint returned;Native(QueryInformationJobObject(job,3,list,(uint)size,out returned),"capacity");uint assigned=unchecked((uint)Marshal.ReadInt32(list)),listed=unchecked((uint)Marshal.ReadInt32(list,4));Check(assigned<=capacity && listed<=capacity,"capacity");for(int i=0;i<listed;i++){ulong pid=unchecked((ulong)Marshal.ReadIntPtr(list,8+i*IntPtr.Size).ToInt64());Check(pid>0 && pid<=uint.MaxValue,"identity");Capture(phase,job,(uint)pid,capacity);}}
  finally{Marshal.FreeHGlobal(list);}
 }
 static void Accounting(Phase phase,IntPtr job,int capacity){var value=Query<BasicAccounting>(job,1,"accounting");if(value.total<phase.total)phase.monotonic=false;phase.total=value.total;phase.maximum=Math.Max(phase.maximum,value.total);Check(phase.samples<uint.MaxValue,"counter_range");phase.samples++;Check(phase.monotonic && phase.total<=capacity,"counter_range");}
 static bool PollTerminals(Phase phase){bool all=true;foreach(var process in phase.generations){if(process.signaled)continue;uint wait=WaitForSingleObject(process.handle,0);Check(wait==0 || wait==258,"wait");if(wait==0){uint code;Native(GetExitCodeProcess(process.handle,out code),"wait");process.signaled=true;process.exitCode=code;}else all=false;}return all;}
 static void Stop(IntPtr job){Closing();Native(TerminateJobObject(job,ForcedExit),"terminate_job");}
 static Phase Execute(string name,Dictionary<string,object> intent,string intentSha,string node,string worker,int capacity){
  var phase=new Phase{name=name,start=Now()};IntPtr job=IntPtr.Zero,port=IntPtr.Zero;var root=new ProcessInformation();bool forced=false;
  try{
   if(name=="cleanup")Check(ClosingAt>=0 && !Expired(),"drain");
   job=CreateJobObject(IntPtr.Zero,null);Native(job!=IntPtr.Zero,"create_job");var host=Map(intent["host"]);var limits=Map(host["limits"]);var extended=new ExtendedLimits();extended.basic.flags=KillOnClose|JobMemory;extended.jobMemory=new UIntPtr((ulong)Integer(limits["memoryBytes"],4096,9007199254740991));Set(job,9,extended);var cpu=new Cpu{flags=CpuHard,rate=(uint)Integer(limits["cpuRate"],1,10000)};Set(job,15,cpu);
   var queried=Query<ExtendedLimits>(job,9,"query_limits");var queriedCpu=Query<Cpu>(job,15,"query_limits");Check(queried.basic.flags==extended.basic.flags && queried.jobMemory==extended.jobMemory && queriedCpu.flags==cpu.flags && queriedCpu.rate==cpu.rate,"query_limits");phase.configured=true;phase.cpuFlags=queriedCpu.flags;phase.cpuRate=queriedCpu.rate;phase.flags=queried.basic.flags;phase.memory=queried.jobMemory.ToUInt64();
   port=CreateIoCompletionPort(new IntPtr(-1),IntPtr.Zero,UIntPtr.Zero,1);Native(port!=IntPtr.Zero,"create_port");Set(job,7,new CompletionPort{key=job,port=port});
   root=Create(job,node,worker,Text(intent["directory"]),name=="primary"?"run":"cleanup",intentSha);
   phase.rootPid=root.pid;phase.rootCreated=Created(root.process);Check(Member(root.process,job),"membership");phase.member=true;phase.generations.Add(new Generation{handle=root.process,pid=root.pid,created=phase.rootCreated});root.process=IntPtr.Zero;
   if(Cancelled && name=="primary"){phase.reason="cancelled";Stop(job);forced=true;}else{uint previous=ResumeThread(root.thread);Native(previous!=0xffffffff,"resume");Check(previous==1,"resume");}
   CloseHandle(root.thread);root.thread=IntPtr.Zero;
   double workDeadline=phase.start+Integer(limits["wallMs"],1,2147483647);
   for(;;){
    Discover(phase,job,port,capacity);Accounting(phase,job,capacity);bool all=PollTerminals(phase);bool rootDone=phase.generations[0].signaled;
    if(rootDone)Closing();
    if(!forced && name=="primary" && (Cancelled || Now()>=workDeadline)){phase.reason=Cancelled?"cancelled":"deadline";Stop(job);forced=true;}
    if(rootDone && all && phase.total==phase.generations.Count){Accounting(phase,job,capacity);Discover(phase,job,port,capacity);if(PollTerminals(phase) && phase.total==phase.generations.Count){phase.coverage=true;if(!forced)phase.reason="completed";break;}}
    if(rootDone && (!all || phase.total!=phase.generations.Count) && !forced){phase.reason="failed";Stop(job);forced=true;}
    Check(!Expired(),"drain");Thread.Sleep(4);
   }
  }catch(OwnerError error){phase.error=error;phase.reason="failed";Closing();if(job!=IntPtr.Zero)TerminateJobObject(job,ForcedExit);}
   catch{phase.error=new OwnerError("unexpected",0);phase.reason="failed";Closing();if(job!=IntPtr.Zero)TerminateJobObject(job,ForcedExit);}
  finally{
   if(root.thread!=IntPtr.Zero)CloseHandle(root.thread);if(root.process!=IntPtr.Zero){Closing();if(job!=IntPtr.Zero)TerminateJobObject(job,ForcedExit);WaitForSingleObject(root.process,(int)Math.Max(0,Math.Min(int.MaxValue,ClosingAt+CleanupMs-Now())));CloseHandle(root.process);}
   if(job!=IntPtr.Zero && !phase.coverage){TerminateJobObject(job,ForcedExit);foreach(var process in phase.generations)if(!process.signaled){uint wait=WaitForSingleObject(process.handle,(int)Math.Max(0,Math.Min(int.MaxValue,ClosingAt+CleanupMs-Now())));if(wait==0){uint code;if(GetExitCodeProcess(process.handle,out code)){process.signaled=true;process.exitCode=code;}}}}
   foreach(var process in phase.generations)if(process.handle!=IntPtr.Zero){CloseHandle(process.handle);process.handle=IntPtr.Zero;}
   if(job!=IntPtr.Zero)CloseHandle(job);if(port!=IntPtr.Zero)CloseHandle(port);phase.end=Now();
  }
  // A stop request never erases a natural nonzero terminal already observed for
  // this exact root generation, including an exit racing the termination API.
  if(phase.generations.Count>0){var actualRoot=phase.generations[0];if(actualRoot.signaled && actualRoot.exitCode.HasValue && actualRoot.exitCode.Value!=0 && !(forced && actualRoot.exitCode.Value==ForcedExit))phase.reason="failed";}
  return phase;
 }
 public static int Main(string[] args){
  Console.OutputEncoding=Utf8;if(args.Length==1 && args[0]=="--version"){Console.WriteLine(Version);return 0;}
  try{
   if(args.Length>0&&args[0].StartsWith("--retained-",StringComparison.Ordinal))return RetainedOperation(args);
   Check(Environment.Is64BitProcess && (args.Length==2||args.Length==3),"descriptor");string directory=Full(args[0]),intentSha=args[1];byte[] raw=Read(Path.Combine(directory,"host-job-intent.json"),65536);Check(Hash(raw)==intentSha,"descriptor");var intent=Map(Json.DeserializeObject(Utf8.GetString(raw)));
   bool retained=Text(intent["schema"])=="scanmux.host-job-intent/v2";
   if(retained)Storage=RetainedIntent(directory,intentSha,raw);else{Keys(intent,"schema","mode","jobId","root","directory","comparison","rootIdentity","host","hostSource","offline","offlineSource","application","assets","nodeIdentity","ownerIdentity","maxProcesses");Check(Text(intent["schema"])=="scanmux.host-job-intent/v1"&&Text(intent["directory"])==directory,"descriptor");var legacyHost=Map(intent["host"]);Keys(legacyHost,"schema","name","scope","offlineProfile","owner","node","limits");Check(Text(legacyHost["schema"])=="scanmux.host-job-profile/v1"&&Text(Map(legacyHost["owner"])["version"])==Version,"descriptor");}
   string mode=Text(intent["mode"]);Check(mode=="scan","descriptor");Guid id;Check(Guid.TryParseExact(Text(intent["jobId"]),"D",out id) && id.ToString()==Text(intent["jobId"]),"descriptor");
   var offline=Map(intent["offline"]);bool bounded=offline.ContainsKey("maxCopyBytes");Check(args.Length==(bounded?3:2),"descriptor");if(bounded){long remaining;Check(long.TryParse(args[2],NumberStyles.None,CultureInfo.InvariantCulture,out remaining)&&remaining>=0&&remaining<=Integer(offline["maxCopyBytes"],1,9007199254740991)&&args[2]==remaining.ToString(CultureInfo.InvariantCulture),"descriptor");CopyBudgetArgument=args[2];}
   var host=Map(intent["host"]);var limits=Map(host["limits"]);Keys(limits,"cpuRate","memoryBytes","wallMs","cleanupTimeoutMs");CleanupMs=Integer(limits["cleanupTimeoutMs"],1,int.MaxValue);Check(Integer(limits["memoryBytes"],4096,9007199254740991)%4096==0,"descriptor");
   string node=Full(Text(Map(host["node"])["path"])),application=Full(Text(intent["application"])),worker=Path.Combine(application,"internal","windows-job-worker.mjs");IdentityFile(node,Map(intent["nodeIdentity"]));Check(HashFile(node,Integer(Map(intent["nodeIdentity"])["bytes"],1,9007199254740991))==Text(Map(host["node"])["sha256"]),"hash");IdentityFile(System.Reflection.Assembly.GetExecutingAssembly().Location,Map(intent["ownerIdentity"]));
   bool workerKnown=false;foreach(object input in (object[])intent["assets"]){var asset=Map(input);Keys(asset,"path","bytes","sha256");string relative=Text(asset["path"]);Check(!Path.IsPathRooted(relative) && relative.IndexOf('\\')<0 && relative.IndexOf(":")<0 && Array.IndexOf(relative.Split('/'),"..")<0,"descriptor");string file=Full(Path.Combine(application,relative.Replace('/',Path.DirectorySeparatorChar)));Check(file.StartsWith(application+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase),"descriptor");Check(HashFile(file,Integer(asset["bytes"],1,9007199254740991))==Text(asset["sha256"]),"hash");if(relative=="internal/windows-job-worker.mjs")workerKnown=true;}
   Check(workerKnown,"descriptor");int maximum=checked((int)Integer(Map(Map(intent["offline"])["scan"])["maxOutputBytes"],1,int.MaxValue));Json.MaxJsonLength=maximum;int capacity=checked((int)Integer(intent["maxProcesses"],2,(maximum-8192)/1024));Check(capacity==(maximum-8192)/1024,"capacity");
   var owner=Obj("pid",GetCurrentProcessId(),"creationFileTime",Created(GetCurrentProcess()));var phases=new List<Phase>();WatchParent();
   Phase primary=Execute("primary",intent,intentSha,node,worker,capacity);phases.Add(primary);if(primary.coverage && primary.error==null)SaveOwned(Path.Combine(directory,"host-job-primary.json"),Obj("schema","scanmux.windows-job-primary/v1","jobId",Text(intent["jobId"]),"intentSha256",intentSha,"owner",owner,"phase",primary.Record()),maximum);
   if(phases[0].coverage && phases[0].error==null && !Expired())phases.Add(Execute("cleanup",intent,intentSha,node,worker,capacity));
   bool closed=phases.Count>0 && phases[phases.Count-1].name=="cleanup";var records=new List<object>();foreach(Phase phase in phases){closed&=phase.coverage && phase.error==null;records.Add(phase.Record());}closed&=!Expired();
   SaveOwned(Path.Combine(directory,"host-job-native.json"),Obj("schema","scanmux.windows-job-owner/v1","version",Version,"intentSha256",intentSha,"jobId",Text(intent["jobId"]),"mode",mode,"phases",records,"state",closed?"closed":"failed","closingStartedMs",ClosingAt<0?null:(object)ClosingAt,"endedMs",Now(),"owner",owner),maximum);
   Console.WriteLine(closed?"closed":"failed");return closed?0:1;
  }catch(RetainedError error){Console.Error.WriteLine(Json.Serialize(Obj("error","retained_write_failed","operation",error.operation,"win32",error.win32)));return 1;}
   catch(OwnerError error){Console.Error.WriteLine(Json.Serialize(Obj("error","host_job_native_failed","operation",error.operation,"win32",error.code)));return 1;}
   catch{Console.Error.WriteLine("{\"error\":\"host_job_native_failed\",\"operation\":\"unexpected\",\"win32\":0}");return 1;}
 }
 [StructLayout(LayoutKind.Sequential)] struct StartupInfo {public uint cb;public IntPtr reserved,desktop,title;public uint x,y,xSize,ySize,xChars,yChars,fill,flags;public ushort show,cbReserved;public IntPtr reserved2,input,output,error;}
 [StructLayout(LayoutKind.Sequential)] struct StartupInfoEx {public StartupInfo startup;public IntPtr attributes;}
 [StructLayout(LayoutKind.Sequential)] struct ProcessInformation {public IntPtr process,thread;public uint pid,tid;}
 [StructLayout(LayoutKind.Sequential)] struct BasicLimits {public long processTime,jobTime;public uint flags;public UIntPtr min,max;public uint active;public UIntPtr affinity;public uint priority,scheduling;}
 [StructLayout(LayoutKind.Sequential)] struct IoCounters {public ulong reads,writes,others,readBytes,writeBytes,otherBytes;}
 [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits {public BasicLimits basic;public IoCounters io;public UIntPtr processMemory,jobMemory,peakProcessMemory,peakJobMemory;}
 [StructLayout(LayoutKind.Sequential)] struct Cpu {public uint flags,rate;}
 [StructLayout(LayoutKind.Sequential)] struct CompletionPort {public IntPtr key,port;}
 [StructLayout(LayoutKind.Sequential)] struct BasicAccounting {public long user,kernel,periodUser,periodKernel;public uint faults,total,active,terminated;}
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,IntPtr data,uint length);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,IntPtr data,uint length,out uint returned);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref IntPtr bytes);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
 [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode,EntryPoint="CreateProcessW")] static extern bool CreateProcess(string application,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string cwd,ref StartupInfoEx startup,out ProcessInformation process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,int milliseconds);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long creation,out long exit,out long kernel,out long user);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")] static extern uint GetCurrentProcessId();
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateIoCompletionPort(IntPtr file,IntPtr existing,UIntPtr key,uint threads);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetQueuedCompletionStatus(IntPtr port,out uint message,out UIntPtr key,out IntPtr payload,uint milliseconds);
}
