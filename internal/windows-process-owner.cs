using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

// Resident owner for processes started by execute(); it never chooses what to launch.
public static class ScanMuxWindowsProcessOwner {
 const string Version="1.4.0";
 const byte ReadyFrame=1,StartFrame=2,StopFrame=3,SpawnedFrame=4,OutFrame=5,ErrFrame=6,ResultFrame=7,InFrame=8,EofFrame=9,RecoveryFrame=10;
 // Delete of a profile that does not exist; measured on Windows 11 by the recovery tests.
 static readonly int[] ProfileMissing={0,unchecked((int)0x80070002),unchecked((int)0x80070490)};
 static readonly System.Text.RegularExpressions.Regex ProfileName=new System.Text.RegularExpressions.Regex("^scanmux-[0-9a-f]{32}$");
 const int MaxRequestBytes=16777216,ChunkBytes=65536,StopBudgetCeilingMs=5000;
 // Job notifications are not guaranteed; waits resolve to the 15.6 ms system tick, so a shorter poll cannot wake sooner.
 const int WakeCeilingMs=16;
 const uint KillOnClose=0x2000,CreateSuspended=4,UnicodeEnvironment=0x400,ExtendedStartup=0x80000,NoWindow=0x08000000,UseStdHandles=0x100,HandleFlagInherit=1,ForcedExit=0xe1000001;
 static readonly IntPtr JobListAttribute=new IntPtr(0x2000D),HandleListAttribute=new IntPtr(0x20002),SecurityCapabilitiesAttribute=new IntPtr(0x20009);
 static readonly UTF8Encoding Utf8=new UTF8Encoding(false,true);
 static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=MaxRequestBytes};
 static readonly Stopwatch Clock=Stopwatch.StartNew();
 static readonly object WriteLock=new object();
 static readonly Dictionary<uint,Request> Open=new Dictionary<uint,Request>();
 static readonly HashSet<uint> Seen=new HashSet<uint>();
 static Stream Output;
 static bool Broken;
 sealed class OwnerError:Exception{public readonly string operation;public readonly uint code;public OwnerError(string op,uint error){operation=op;code=error;}}
 sealed class Spec{public string path,sha256,cwd,environment,snapshot,work;public string[] args;public long maxOutput;public int deadlineMs,stopBudgetMs;}
 sealed class Outcome{public string reason,operation;public uint? code;public uint win32;}
 sealed class Request {
  public uint id;public double started,stopDeadline=double.MaxValue;public long maxOutput,forwarded;public bool closed;
  string cause;IntPtr job,port;
  readonly Queue<byte[]> input=new Queue<byte[]>();bool inputEnded;
  public void Input(byte[] chunk){lock(input){if(inputEnded)return;if(chunk==null)inputEnded=true;else input.Enqueue(chunk);Monitor.PulseAll(input);}}
  public byte[] NextInput(){lock(input){while(input.Count==0 && !inputEnded)Monitor.Wait(input);return input.Count>0?input.Dequeue():null;}}
  public void Attach(IntPtr j,IntPtr p){lock(this){job=j;port=p;}}
  public void Detach(){lock(this){job=IntPtr.Zero;port=IntPtr.Zero;}}
  public string Cause(){lock(this)return cause;}
  public void Stop(string why){lock(this){if(cause==null)cause=why;if(port!=IntPtr.Zero)PostQueuedCompletionStatus(port,0,UIntPtr.Zero,IntPtr.Zero);}}
  public void Terminate(){lock(this){if(job!=IntPtr.Zero)TerminateJobObject(job,ForcedExit);}}
 }
 static Dictionary<string,object> Obj(params object[] pairs){var result=new Dictionary<string,object>();for(int i=0;i<pairs.Length;i+=2)result.Add((string)pairs[i],pairs[i+1]);return result;}
 static Dictionary<string,object> Map(object input){var map=input as Dictionary<string,object>;Check(map!=null,"descriptor");return map;}
 static void Keys(Dictionary<string,object> value,params string[] keys){Check(value.Count==keys.Length,"descriptor");foreach(string key in keys)Check(value.ContainsKey(key),"descriptor");}
 static void Check(bool value,string operation){if(!value)throw new OwnerError(operation,0);}
 static void Native(bool value,string operation){int error=Marshal.GetLastWin32Error();if(!value)throw new OwnerError(operation,unchecked((uint)error));}
 static string Text(object value){Check(value is string && ((string)value).IndexOf('\0')<0,"descriptor");return (string)value;}
 static long Integer(object value,long min,long max){Check(value is int || value is long,"descriptor");long n=Convert.ToInt64(value,CultureInfo.InvariantCulture);Check(n>=min && n<=max,"descriptor");return n;}
 static double Now(){return Clock.Elapsed.TotalMilliseconds;}
 static string Full(string value){Check(value.Length>=3 && Char.IsLetter(value[0]) && value[1]==':' && (value[2]=='\\' || value[2]=='/') && value.Substring(2).IndexOf(':')<0 && value.IndexOfAny(new char[]{'\r','\n'})<0,"descriptor");return Path.GetFullPath(value);}
 static string Quote(string value){if(value.Length>0 && value.IndexOfAny(new char[]{' ','\t','\n','\v','"'})<0)return value;var b=new StringBuilder("\"");int slashes=0;foreach(char c in value){if(c=='\\'){slashes++;continue;}if(c=='"')b.Append('\\',slashes*2+1);else b.Append('\\',slashes);slashes=0;b.Append(c);}b.Append('\\',slashes*2).Append('"');return b.ToString();}
 static string Hex(byte[] bytes){return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant();}
 static string Created(IntPtr process){long c,e,k,u;Native(GetProcessTimes(process,out c,out e,out k,out u),"identity");Check(c>0,"identity");return c.ToString(CultureInfo.InvariantCulture);}
 static void Set<T>(IntPtr job,int kind,T value){int size=Marshal.SizeOf(typeof(T));IntPtr data=Marshal.AllocHGlobal(size);try{Marshal.StructureToPtr(value,data,false);Native(SetInformationJobObject(job,kind,data,(uint)size),"set_limits");}finally{Marshal.FreeHGlobal(data);}}
 static T Query<T>(IntPtr job,int kind,string op){int size=Marshal.SizeOf(typeof(T));IntPtr data=Marshal.AllocHGlobal(size);try{uint returned;Native(QueryInformationJobObject(job,kind,data,(uint)size,out returned),op);return (T)Marshal.PtrToStructure(data,typeof(T));}finally{Marshal.FreeHGlobal(data);}}
 static uint Active(IntPtr job){return Query<BasicAccounting>(job,1,"accounting").active;}

 static Spec Parse(byte[] body){
  var m=Map(Json.DeserializeObject(Utf8.GetString(body)));
  if(m.ContainsKey("appContainer"))Keys(m,"path","sha256","args","cwd","env","maxOutputBytes","deadlineMs","stopBudgetMs","appContainer");
  else Keys(m,"path","sha256","args","cwd","env","maxOutputBytes","deadlineMs","stopBudgetMs");
  var s=new Spec{path=Full(Text(m["path"])),sha256=Text(m["sha256"]),cwd=Full(Text(m["cwd"])),maxOutput=Integer(m["maxOutputBytes"],0,int.MaxValue),
   deadlineMs=(int)Integer(m["deadlineMs"],1,int.MaxValue),stopBudgetMs=(int)Integer(m["stopBudgetMs"],1,StopBudgetCeilingMs)};
  Check(s.sha256.Length==64,"descriptor");foreach(char c in s.sha256)Check((c>='0'&&c<='9')||(c>='a'&&c<='f'),"descriptor");
  var args=m["args"] as object[];Check(args!=null,"descriptor");s.args=new string[args.Length];for(int i=0;i<args.Length;i++)s.args[i]=Text(args[i]);
  if(m.ContainsKey("appContainer")){var ac=Map(m["appContainer"]);Keys(ac,"snapshot","work");s.snapshot=Full(Text(ac["snapshot"]));s.work=Full(Text(ac["work"]));}
  var env=Map(m["env"]);
  // GetTempPath2 adds Packages/<profile>/AC/Temp to LOCALAPPDATA for an AppContainer.
  if(s.work!=null){foreach(string key in new List<string>(env.Keys))if(String.Equals(key,"LOCALAPPDATA",StringComparison.OrdinalIgnoreCase))env.Remove(key);env["LOCALAPPDATA"]=Path.Combine(s.work,"local");}
  var names=new List<string>(env.Keys);names.Sort(StringComparer.OrdinalIgnoreCase);var block=new StringBuilder();
  for(int i=0;i<names.Count;i++){string name=names[i];Check(name.Length>0 && name.IndexOf('=')<0 && name.IndexOf('\0')<0 && (i==0 || !String.Equals(names[i-1],name,StringComparison.OrdinalIgnoreCase)),"descriptor");block.Append(name).Append('=').Append(Text(env[name])).Append('\0');}
  s.environment=block.Append('\0').ToString();
  return s;
 }

 static bool Under(string parent,string child){return String.Equals(parent,child,StringComparison.OrdinalIgnoreCase) || child.StartsWith(parent.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase);}
 static void NoReparseAncestors(string path){for(string p=path;p!=null;p=Path.GetDirectoryName(p))Check((File.GetAttributes(p)&FileAttributes.ReparsePoint)==0,"appcontainer_roots_invalid");}
 // A hardlinked file shares one ACL with its other names, so a grant would also reach a path outside the root.
 static uint Links(string path){
  using(var handle=CreateFile(path,0x80,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){
   Native(!handle.IsInvalid,"appcontainer_roots_invalid");FileInformation info;Native(GetFileInformationByHandle(handle,out info),"appcontainer_roots_invalid");return info.links;
  }
 }
 static void NoReparseTree(string path){
  Check((File.GetAttributes(path)&FileAttributes.ReparsePoint)==0,"appcontainer_roots_invalid");
  if(Directory.Exists(path))foreach(string child in Directory.GetFileSystemEntries(path))NoReparseTree(child);
  else Check(Links(path)==1,"appcontainer_hardlink_present");
 }
 static IntPtr TokenData(IntPtr token,int kind,string operation){int size;GetTokenInformation(token,kind,IntPtr.Zero,0,out size);Check(size>0,operation);IntPtr data=Marshal.AllocHGlobal(size);try{Native(GetTokenInformation(token,kind,data,size,out size),operation);return data;}catch{Marshal.FreeHGlobal(data);throw;}}
 static int TokenNumber(IntPtr token,int kind,string operation){IntPtr data=TokenData(token,kind,operation);try{return Marshal.ReadInt32(data);}finally{Marshal.FreeHGlobal(data);}}
 static void VerifyToken(IntPtr process,SecurityIdentifier expected){
  string operation=expected==null?"appcontainer_owner_token_invalid":"appcontainer_token_mismatch";
  IntPtr token;Native(OpenProcessToken(process,8,out token),operation);
  try{
   Check(TokenNumber(token,20,operation)==0,expected==null?"appcontainer_elevated_owner":operation);
   Check(TokenNumber(token,29,operation)==(expected==null?0:1),operation);
   if(expected!=null){Check(TokenNumber(token,30,operation)==0,operation);IntPtr data=TokenData(token,31,operation);try{IntPtr sid=Marshal.ReadIntPtr(data);Check(sid!=IntPtr.Zero && expected.Equals(new SecurityIdentifier(sid)),operation);}finally{Marshal.FreeHGlobal(data);}}
  }finally{CloseHandle(token);}
 }
 sealed class Grant {
  public string path;public FileSystemAccessRule[] rules;
  public Grant(string p,params FileSystemAccessRule[] r){path=p;rules=r;}
  public void Apply(){var acl=Directory.GetAccessControl(path,AccessControlSections.Access);foreach(var rule in rules)acl.AddAccessRule(rule);Directory.SetAccessControl(path,acl);}
  public void Remove(){var acl=Directory.GetAccessControl(path,AccessControlSections.Access);foreach(var rule in rules)acl.RemoveAccessRuleSpecific(rule);Directory.SetAccessControl(path,acl);}
 }
 const InheritanceFlags Tree=InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit;
 static FileSystemAccessRule Rule(SecurityIdentifier sid,FileSystemRights rights,InheritanceFlags inherit,PropagationFlags propagation){return new FileSystemAccessRule(sid,rights,inherit,propagation,AccessControlType.Allow);}
 sealed class Container {
  public IntPtr sid;public SecurityIdentifier identity;string profile;bool profileCreated,journaled;
  readonly List<Grant> grants=new List<Grant>();
  public void Prepare(Spec s){
   VerifyToken(GetCurrentProcess(),null);
   string bin=Path.GetDirectoryName(s.path);string[] roots={s.snapshot,s.work,bin};
   for(int i=0;i<roots.Length;i++){
    roots[i]=roots[i].TrimEnd('\\');Check(Directory.Exists(roots[i]) && Path.GetDirectoryName(roots[i])!=null,"appcontainer_roots_invalid");
    NoReparseAncestors(roots[i]);NoReparseTree(roots[i]);
    for(int j=0;j<i;j++)Check(!Under(roots[i],roots[j]) && !Under(roots[j],roots[i]),"appcontainer_roots_invalid");
   }
   Check(String.Equals(Path.GetDirectoryName(roots[1]),Path.GetDirectoryName(roots[2]),StringComparison.OrdinalIgnoreCase) && Under(s.work,s.cwd),"appcontainer_roots_invalid");
   profile="scanmux-"+Guid.NewGuid().ToString("N");
   // The journal names the profile and its roots before the profile exists, so a later owner can reclaim both after a crash.
   Begin(profile,roots);journaled=true;
   int hr;
   try{hr=CreateAppContainerProfile(profile,profile,"Disposable ScanMux tool",IntPtr.Zero,0,out sid);}
   catch(DllNotFoundException error){throw new OwnerError("appcontainer_profile_unavailable",unchecked((uint)error.HResult));}
   catch(EntryPointNotFoundException error){throw new OwnerError("appcontainer_profile_unavailable",unchecked((uint)error.HResult));}
   if(hr!=0)throw new OwnerError(hr==unchecked((int)0x80004001)?"appcontainer_profile_unavailable":"appcontainer_profile_failed",unchecked((uint)hr));
   profileCreated=true;identity=new SecurityIdentifier(sid);
   Check(identity.Equals(Derived(profile)),"appcontainer_profile_failed");
   Directory.CreateDirectory(Path.Combine(s.work,"local","Packages",profile,"AC","Temp"));
   // Check the newly created suffix too, before granting access to any root.
   NoReparseTree(s.work);
   Add(s.snapshot,Rule(identity,FileSystemRights.ReadAndExecute,Tree,PropagationFlags.None));
   Add(bin,Rule(identity,FileSystemRights.ReadAndExecute,Tree,PropagationFlags.None));
   // W itself can be listed and filled but not deleted, renamed or re-permissioned; only its contents get Modify.
   Add(s.work,Rule(identity,FileSystemRights.Modify,Tree,PropagationFlags.InheritOnly),
    Rule(identity,FileSystemRights.ReadAndExecute|FileSystemRights.CreateFiles|FileSystemRights.CreateDirectories,InheritanceFlags.None,PropagationFlags.None));
  }
  void Add(string path,params FileSystemAccessRule[] rules){var grant=new Grant(path,rules);grants.Add(grant);try{grant.Apply();}catch(Exception error){throw new OwnerError("appcontainer_grant_failed",unchecked((uint)error.HResult));}}
  public static void NoResidual(string path,SecurityIdentifier sid){
   Check((File.GetAttributes(path)&FileAttributes.ReparsePoint)==0,"appcontainer_cleanup_failed");
   FileSystemSecurity acl=Directory.Exists(path)?(FileSystemSecurity)Directory.GetAccessControl(path,AccessControlSections.Access):File.GetAccessControl(path,AccessControlSections.Access);
   foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))Check(!rule.IdentityReference.Equals(sid),"appcontainer_cleanup_failed");
   if(Directory.Exists(path))foreach(string child in Directory.GetFileSystemEntries(path))NoResidual(child,sid);
  }
  public bool Cleanup(){
   bool clean=true;
   for(int i=grants.Count-1;i>=0;i--)try{grants[i].Remove();}catch{clean=false;}
   foreach(var grant in grants)try{NoResidual(grant.path,identity);}catch{clean=false;}
   // Do not delete the profile if its SID still has access to any request tree.
   if(clean && profileCreated)try{clean=DeleteAppContainerProfile(profile)==0;}catch{clean=false;}
   // A failed END write only makes a later owner repeat the reclaim, which finds nothing left.
   if(clean && journaled)try{End(profile);}catch{}
   return clean;
  }
  public void Release(){if(sid!=IntPtr.Zero){FreeSid(sid);sid=IntPtr.Zero;}}
 }

 // One journal file per owner, held without sharing for the owner's lifetime. The OS releases it when the owner dies,
 // so a file another owner can open exclusively belongs to a dead owner; a sharing violation means it is alive.
 static readonly object JournalLock=new object();
 static FileStream Journal;
 static string JournalDirectory;
 static int OpenEntries;
 static SecurityIdentifier Derived(string name){IntPtr sid;Check(DeriveAppContainerSidFromAppContainerName(name,out sid)==0,"appcontainer_profile_failed");try{return new SecurityIdentifier(sid);}finally{FreeSid(sid);}}
 static string LocalAppData(){IntPtr p;Check(SHGetKnownFolderPath(new Guid("F1B32785-6FBA-4FCF-9D55-7B8E7F157091"),0,IntPtr.Zero,out p)==0,"journal");try{return Marshal.PtrToStringUni(p);}finally{Marshal.FreeCoTaskMem(p);}}
 static void PrivateDirectory(string path){
  SecurityIdentifier user;using(var identity=WindowsIdentity.GetCurrent())user=identity.User;
  if(!Directory.Exists(path)){var created=new DirectorySecurity();created.SetAccessRuleProtection(true,false);created.AddAccessRule(Rule(user,FileSystemRights.FullControl,Tree,PropagationFlags.None));Directory.CreateDirectory(path,created);}
  Check((File.GetAttributes(path)&FileAttributes.ReparsePoint)==0,"journal");
  var acl=Directory.GetAccessControl(path,AccessControlSections.Access|AccessControlSections.Owner);
  Check(acl.AreAccessRulesProtected && user.Equals(acl.GetOwner(typeof(SecurityIdentifier))),"journal");
  foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))Check(rule.AccessControlType==AccessControlType.Allow && user.Equals(rule.IdentityReference),"journal");
 }
 static bool Elevated(){
  // Unknown counts as elevated: skipping the journal is harmless, creating it from an elevated token is not.
  IntPtr token;if(!OpenProcessToken(GetCurrentProcess(),8,out token))return true;
  try{return TokenNumber(token,20,"identity")!=0;}catch{return true;}finally{CloseHandle(token);}
 }
 static void OpenJournal(){
  try{
   string directory=Path.Combine(LocalAppData(),"scanmux-owner-journal");PrivateDirectory(directory);
   Journal=new FileStream(Path.Combine(directory,Guid.NewGuid().ToString("N")+".jnl"),FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None);JournalDirectory=directory;
  }catch{Journal=null;}
 }
 static void Append(FileStream stream,Dictionary<string,object> entry){byte[] line=Utf8.GetBytes(Json.Serialize(entry)+"\n");stream.Seek(0,SeekOrigin.End);stream.Write(line,0,line.Length);stream.Flush(true);}
 static void Begin(string profile,string[] roots){
  lock(JournalLock){
   try{Check(Journal!=null,"appcontainer_journal_failed");Append(Journal,Obj("begin",profile,"roots",roots));OpenEntries++;}
   catch(OwnerError error){throw new OwnerError("appcontainer_journal_failed",error.code);}
   catch(Exception error){throw new OwnerError("appcontainer_journal_failed",unchecked((uint)error.HResult));}
  }
 }
 static void End(string profile){lock(JournalLock){Append(Journal,Obj("end",profile));OpenEntries--;}}
 // A clean exit removes the journal; open entries stay for the next owner.
 static void CloseJournal(){lock(JournalLock){if(Journal==null || OpenEntries!=0)return;string name=Journal.Name;Journal.Dispose();Journal=null;try{File.Delete(name);}catch{}}}

 static void Recover(){
  int recovered=0,kept=0;var codes=new SortedSet<string>(StringComparer.Ordinal);
  try{
   if(JournalDirectory==null)codes.Add("appcontainer_journal_failed");
   else foreach(string file in Directory.GetFiles(JournalDirectory,"*.jnl")){
    FileStream stream;
    try{stream=new FileStream(file,FileMode.Open,FileAccess.ReadWrite,FileShare.None);}
    // A journal removed after listing belonged to an owner that exited cleanly, so nothing is left to reclaim.
    catch(FileNotFoundException){continue;}
    catch(IOException error){if((error.HResult&0xffff)==32)continue;if(!File.Exists(file))continue;codes.Add("appcontainer_recovery_liveness_unknown");kept++;continue;}
    catch{if(!File.Exists(file))continue;codes.Add("appcontainer_recovery_liveness_unknown");kept++;continue;}
    bool finished;
    using(stream)finished=RecoverJournal(stream,codes,ref recovered,ref kept);
    if(finished)try{File.Delete(file);}catch{codes.Add("appcontainer_recovery_journal_delete_failed");}
   }
  }catch{codes.Add("appcontainer_recovery_failed");}
  byte[] body=Utf8.GetBytes(Json.Serialize(Obj("recovered",recovered,"kept",kept,"codes",new List<string>(codes))));
  lock(WriteLock)Emit(RecoveryFrame,0,body,body.Length);
 }
 static bool RecoverJournal(FileStream stream,SortedSet<string> codes,ref int recovered,ref int kept){
  var bytes=new byte[stream.Length];Check(Fill(stream,bytes,0,bytes.Length)==bytes.Length,"journal");
  // Only the last line can be torn, because every line is flushed before the next is written. Drop it before appending.
  int valid=Array.LastIndexOf(bytes,(byte)10)+1;if(valid<bytes.Length)stream.SetLength(valid);
  var open=new Dictionary<string,string[]>(StringComparer.Ordinal);var order=new List<string>();
  try{
   foreach(string line in Utf8.GetString(bytes,0,valid).Split(new char[]{'\n'},StringSplitOptions.RemoveEmptyEntries)){
    var entry=Map(Json.DeserializeObject(line));
    if(entry.ContainsKey("begin")){
     Keys(entry,"begin","roots");string name=Text(entry["begin"]);Check(ProfileName.IsMatch(name) && !open.ContainsKey(name),"journal");
     var listed=entry["roots"] as object[];Check(listed!=null && listed.Length==3,"journal");
     var roots=new string[3];for(int i=0;i<3;i++)roots[i]=Full(Text(listed[i]));open[name]=roots;order.Add(name);
    }else{Keys(entry,"end");open.Remove(Text(entry["end"]));}
   }
  }catch{codes.Add("appcontainer_recovery_journal_invalid");kept++;return false;}
  bool finished=true;
  foreach(string name in order){
   if(!open.ContainsKey(name))continue;
   if(Reclaim(name,open[name],codes)){Append(stream,Obj("end",name));recovered++;}else{kept++;finished=false;}
  }
  return finished;
 }
 // Reclaim only removes ACEs for the profile's SID and never adds one, so it cannot widen access.
 static bool Reclaim(string name,string[] roots,SortedSet<string> codes){
  SecurityIdentifier sid;
  try{sid=Derived(name);}catch{codes.Add("appcontainer_recovery_failed");return false;}
  bool clean=true;
  foreach(string root in roots){
   // A missing root has nothing left to reclaim. A root that is now a reparse point is left untouched.
   try{if(!Directory.Exists(root) && !File.Exists(root))continue;NoReparseAncestors(root);}
   catch{codes.Add("appcontainer_recovery_root_invalid");clean=false;continue;}
   try{var acl=Directory.GetAccessControl(root,AccessControlSections.Access);acl.PurgeAccessRules(sid);Directory.SetAccessControl(root,acl);Container.NoResidual(root,sid);}
   catch{codes.Add("appcontainer_recovery_residual_ace");clean=false;}
  }
  if(!clean)return false;
  int hr;try{hr=DeleteAppContainerProfile(name);}catch{hr=-1;}
  if(Array.IndexOf(ProfileMissing,hr)<0){codes.Add("appcontainer_recovery_profile_failed");return false;}
  return true;
 }

 static void Emit(byte kind,uint id,byte[] body,int count){
  if(Broken)return;var header=new byte[9];Array.Copy(BitConverter.GetBytes((uint)(5+count)),0,header,0,4);header[4]=kind;Array.Copy(BitConverter.GetBytes(id),0,header,5,4);
  try{Output.Write(header,0,9);Output.Write(body,0,count);Output.Flush();}catch(IOException){Broken=true;}
 }
 static void Send(Request r,byte kind,byte[] body){lock(WriteLock){if(!r.closed)Emit(kind,r.id,body,body.Length);}}
 static void Forward(Request r,byte kind,byte[] buffer,int count){lock(WriteLock){if(r.closed || r.forwarded>r.maxOutput)return;int n=(int)Math.Min(count,r.maxOutput+1-r.forwarded);r.forwarded+=n;Emit(kind,r.id,buffer,n);}}
 static void Finish(Request r,Outcome o){
  byte[] body=Utf8.GetBytes(Json.Serialize(Obj("reason",o.reason,"code",o.code,"operation",o.operation,"win32",o.win32)));
  lock(WriteLock){Emit(ResultFrame,r.id,body,body.Length);r.closed=true;}
  lock(Open)Open.Remove(r.id);
 }
 static Outcome Failure(string reason,string operation,uint win32){return new Outcome{reason=reason,operation=operation,win32=win32};}

 static int Fill(Stream input,byte[] buffer,int offset,int count){int total=0,read;while(total<count && (read=input.Read(buffer,offset+total,count-total))>0)total+=read;return total;}
 static bool ReadFrame(Stream input,out byte kind,out uint id,out byte[] body){
  kind=0;id=0;body=null;var header=new byte[9];int got=Fill(input,header,0,4);if(got==0)return false;Check(got==4,"frame_truncated");
  uint length=BitConverter.ToUInt32(header,0);Check(length>=5 && length<=5u+MaxRequestBytes,"frame_oversize");Check(Fill(input,header,4,5)==5,"frame_truncated");
  kind=header[4];id=BitConverter.ToUInt32(header,5);body=new byte[length-5];Check(Fill(input,body,0,body.Length)==body.Length,"frame_truncated");return true;
 }
 static void Dispatch(byte kind,uint id,byte[] body){
  if(kind==StartFrame){
   Request r;lock(Open){Check(id!=0 && Seen.Add(id),"duplicate_start");r=new Request{id=id,started=Now()};Open.Add(id,r);}
   var worker=new Thread(delegate(){Run(r,body);});worker.IsBackground=true;worker.Start();return;
  }
  if(kind==InFrame || kind==EofFrame){
   Check(kind==InFrame || body.Length==0,"frame_kind");
   Request open;lock(Open)Open.TryGetValue(id,out open);if(open!=null)open.Input(kind==InFrame?body:null);return;
  }
  Check(kind==StopFrame,"frame_kind");string why=Utf8.GetString(body);Check(why=="cancelled" || why=="output_limit","stop_cause");
  Request target;lock(Open)Open.TryGetValue(id,out target);if(target!=null)target.Stop(why);
 }
 static void TerminateAll(){List<Request> open;lock(Open)open=new List<Request>(Open.Values);foreach(var r in open)r.Terminate();}

 static void Pipe(out SafeFileHandle read,out SafeFileHandle write,bool childReads){
  var attributes=new SecurityAttributes{length=(uint)Marshal.SizeOf(typeof(SecurityAttributes)),inherit=1};
  Native(CreatePipe(out read,out write,ref attributes,0),"create_pipe");Native(SetHandleInformation(childReads?write:read,HandleFlagInherit,0),"create_pipe");
 }
 static Thread Pump(Request r,SafeFileHandle handle,byte kind){
  var stream=new FileStream(handle,FileAccess.Read,1,false);
  var t=new Thread(delegate(){var buffer=new byte[ChunkBytes];try{int read;while((read=stream.Read(buffer,0,buffer.Length))>0)Forward(r,kind,buffer,read);}catch(IOException){}finally{stream.Dispose();}});
  t.IsBackground=true;t.Start();return t;
 }
 static void Feed(Request r,SafeFileHandle handle){
  var stream=new FileStream(handle,FileAccess.Write,1,false);
  var t=new Thread(delegate(){try{byte[] chunk;while((chunk=r.NextInput())!=null)stream.Write(chunk,0,chunk.Length);}catch(IOException){}finally{try{stream.Dispose();}catch(IOException){}}});
  t.IsBackground=true;t.Start();
 }
 static bool Join(Thread[] threads,double until){foreach(var t in threads)if(!t.Join((int)Math.Max(0,Math.Ceiling(until-Now()))))return false;return true;}

 static ProcessInformation Create(IntPtr job,Spec s,Container container,SafeFileHandle stdin,SafeFileHandle stdout,SafeFileHandle stderr){
  var startup=new StartupInfoEx();startup.startup.cb=(uint)Marshal.SizeOf(typeof(StartupInfoEx));startup.startup.flags=UseStdHandles;
  startup.startup.input=stdin.DangerousGetHandle();startup.startup.output=stdout.DangerousGetHandle();startup.startup.error=stderr.DangerousGetHandle();
  IntPtr attributes=IntPtr.Zero,jobs=IntPtr.Zero,handles=IntPtr.Zero,environment=IntPtr.Zero,capabilities=IntPtr.Zero;bool initialized=false;
  try{
   // The image stays open without write sharing so the hashed bytes are the bytes that start.
   using(var image=new FileStream(s.path,FileMode.Open,FileAccess.Read,FileShare.Read)){
    Check((File.GetAttributes(s.path)&FileAttributes.ReparsePoint)==0,"descriptor");
    using(var sha=SHA256.Create())Check(Hex(sha.ComputeHash(image))==s.sha256,"tool_digest_mismatch");
    int count=container==null?2:3;
    IntPtr size=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,count,0,ref size);Check(size.ToInt64()>0,"attributes");
    attributes=Marshal.AllocHGlobal(size);Native(InitializeProcThreadAttributeList(attributes,count,0,ref size),"attributes");initialized=true;
    jobs=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobs,job);
    Native(UpdateProcThreadAttribute(attributes,0,JobListAttribute,jobs,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero),"attributes");
    handles=Marshal.AllocHGlobal(IntPtr.Size*3);Marshal.WriteIntPtr(handles,0,startup.startup.input);Marshal.WriteIntPtr(handles,IntPtr.Size,startup.startup.output);Marshal.WriteIntPtr(handles,IntPtr.Size*2,startup.startup.error);
    Native(UpdateProcThreadAttribute(attributes,0,HandleListAttribute,handles,new IntPtr(IntPtr.Size*3),IntPtr.Zero,IntPtr.Zero),"attributes");
    if(container!=null){var caps=new SecurityCapabilities{sid=container.sid};capabilities=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityCapabilities)));Marshal.StructureToPtr(caps,capabilities,false);Native(UpdateProcThreadAttribute(attributes,0,SecurityCapabilitiesAttribute,capabilities,new IntPtr(Marshal.SizeOf(typeof(SecurityCapabilities))),IntPtr.Zero,IntPtr.Zero),"attributes");}
    startup.attributes=attributes;environment=Marshal.StringToHGlobalUni(s.environment);
    var command=new StringBuilder(Quote(s.path));foreach(string arg in s.args)command.Append(' ').Append(Quote(arg));
    ProcessInformation process;
    Native(CreateProcess(s.path,command,IntPtr.Zero,IntPtr.Zero,true,CreateSuspended|ExtendedStartup|UnicodeEnvironment|NoWindow,environment,s.cwd,ref startup,out process),"create_process");
    return process;
   }
  }catch(OwnerError error){if(container!=null && error.operation!="tool_digest_mismatch")throw new OwnerError("appcontainer_create_failed",error.code);throw;}
  catch(Exception error){if(container!=null)throw new OwnerError("appcontainer_create_failed",unchecked((uint)error.HResult));throw;}
  finally{if(initialized)DeleteProcThreadAttributeList(attributes);foreach(IntPtr block in new[]{attributes,jobs,handles,environment,capabilities})if(block!=IntPtr.Zero)Marshal.FreeHGlobal(block);}
 }
 static Outcome Supervise(Request r,IntPtr job,IntPtr port,IntPtr root,Spec s){
  double deadline=r.started+s.deadlineMs;string cause=null;
  for(;;){
   double now=Now();
   if(cause==null){cause=r.Cause()??(now>=deadline?"timeout":null);if(cause!=null){r.stopDeadline=now+s.stopBudgetMs;Native(TerminateJobObject(job,ForcedExit),"terminate_job");}}
   if(now>=r.stopDeadline)return Failure("termination_unverified","stop_budget",0);
   uint wait=WaitForSingleObject(root,0);Check(wait==0 || wait==258,"wait");
   // One empty accounting sample is never taken as proof of drain; the second, taken after Sleep(1) yields to the scheduler, must agree.
   if(wait==0 && Active(job)==0){
    Thread.Sleep(1);
    if(Active(job)==0){if(Now()>=r.stopDeadline)return Failure("termination_unverified","stop_budget",0);uint code;Native(GetExitCodeProcess(root,out code),"exit_code");return new Outcome{reason=cause??"exit",code=code};}
   }
   double next=Math.Min(cause==null?deadline:r.stopDeadline,now+WakeCeilingMs);
   uint message;UIntPtr key;IntPtr payload;GetQueuedCompletionStatus(port,out message,out key,out payload,(uint)Math.Max(0,Math.Ceiling(next-now)));
  }
 }
 static bool StopBeforeResume(IntPtr job,IntPtr root,int budget){
  try{
   Native(TerminateJobObject(job,ForcedExit),"terminate_job");double until=Now()+budget;
   while(Now()<until){if(WaitForSingleObject(root,0)==0 && Active(job)==0){Thread.Sleep(1);if(Now()<until && Active(job)==0)return true;}Thread.Sleep(1);}
  }catch{}
  return false;
 }
 static void Run(Request r,byte[] body){
  Outcome o;bool created=false,resumed=false;Container container=null;Spec s=null;IntPtr job=IntPtr.Zero,port=IntPtr.Zero,root=IntPtr.Zero,thread=IntPtr.Zero;
  SafeFileHandle inRead=null,inWrite=null,outRead=null,outWrite=null,errRead=null,errWrite=null;
  try{
   s=Parse(body);r.maxOutput=s.maxOutput;
   if(s.work!=null){container=new Container();container.Prepare(s);}
   job=CreateJobObject(IntPtr.Zero,null);Native(job!=IntPtr.Zero,"create_job");
   var limits=new ExtendedLimits();limits.basic.flags=KillOnClose;Set(job,9,limits);Check(Query<ExtendedLimits>(job,9,"query_limits").basic.flags==KillOnClose,"query_limits");
   port=CreateIoCompletionPort(new IntPtr(-1),IntPtr.Zero,UIntPtr.Zero,1);Native(port!=IntPtr.Zero,"create_port");Set(job,7,new CompletionPort{key=job,port=port});
   r.Attach(job,port);
   Pipe(out inRead,out inWrite,true);Pipe(out outRead,out outWrite,false);Pipe(out errRead,out errWrite,false);
   var process=Create(job,s,container,inRead,outWrite,errWrite);created=true;root=process.process;thread=process.thread;
   inRead.Dispose();outWrite.Dispose();errWrite.Dispose();
   bool member;Native(IsProcessInJob(root,job,out member),"membership");Check(member,"membership");
   if(container!=null)VerifyToken(root,container.identity);
   Send(r,SpawnedFrame,Utf8.GetBytes(Json.Serialize(Obj("pid",process.pid,"creationTime",Created(root)))));
   if(r.Cause()==null){uint previous=ResumeThread(thread);Native(previous!=0xffffffff,"resume");resumed=true;Check(previous==1,"resume");}
   var pumps=new[]{Pump(r,outRead,OutFrame),Pump(r,errRead,ErrFrame)};outRead=null;errRead=null;
   Feed(r,inWrite);inWrite=null;
   o=Supervise(r,job,port,root,s);
   if(o.reason!="termination_unverified" && !Join(pumps,Math.Min(r.stopDeadline,Now()+s.stopBudgetMs)))o=Failure("termination_unverified","output_drain",0);
  }catch(OwnerError error){
   bool stopped=!created || (container!=null && !resumed && StopBeforeResume(job,root,s.stopBudgetMs));
   o=Failure(stopped?"spawn_failed":"termination_unverified",error.operation,error.code);
  }catch{
   bool stopped=!created || (container!=null && !resumed && StopBeforeResume(job,root,s.stopBudgetMs));
   o=Failure(stopped?"spawn_failed":"termination_unverified",container!=null && stopped?"appcontainer_setup_failed":"unexpected",0);
  }
  finally{
   r.Detach();r.Input(null);
   if(job!=IntPtr.Zero){TerminateJobObject(job,ForcedExit);CloseHandle(job);}
   if(port!=IntPtr.Zero)CloseHandle(port);if(thread!=IntPtr.Zero)CloseHandle(thread);if(root!=IntPtr.Zero)CloseHandle(root);
   foreach(var handle in new[]{inRead,inWrite,outRead,outWrite,errRead,errWrite})if(handle!=null)handle.Dispose();
  }
  if(container!=null){if(o.reason!="termination_unverified" && !container.Cleanup())o=Failure("spawn_failed","appcontainer_cleanup_failed",0);container.Release();}
  Finish(r,o);
 }

 public static int Main(string[] args){
  if(args.Length==1 && args[0]=="--version"){Console.Out.Write(Version+"\n");return 0;}
  if(args.Length!=0 || !Environment.Is64BitProcess)return 2;
  Output=Console.OpenStandardOutput();
  // An elevated owner refuses AppContainer requests, so it needs no journal. It must not create the folder either:
  // an elevated token would make Administrators its owner and lock every later non-elevated owner out.
  bool elevated=Elevated();
  if(!elevated)OpenJournal();
  lock(WriteLock)Emit(ReadyFrame,0,Encoding.ASCII.GetBytes(Version),Version.Length);
  // After Ready, so a slow reclaim cannot trip the caller's ready timeout.
  if(!elevated){var recovery=new Thread(Recover);recovery.IsBackground=true;recovery.Start();}
  int status=0;
  try{var input=Console.OpenStandardInput();byte kind;uint id;byte[] body;while(ReadFrame(input,out kind,out id,out body))Dispatch(kind,id,body);}
  catch{status=1;}
  TerminateAll();
  // Workers are background threads; returning at once would cut their Cleanup short. The caller kills the owner after its stop budget.
  for(double until=Now()+StopBudgetCeilingMs-500;;){lock(Open){if(Open.Count==0)break;}if(Now()>=until)break;Thread.Sleep(10);}
  CloseJournal();return status;
 }

 [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {public uint length;public IntPtr descriptor;public int inherit;}
 [StructLayout(LayoutKind.Sequential)] struct StartupInfo {public uint cb;public IntPtr reserved,desktop,title;public uint x,y,xSize,ySize,xChars,yChars,fill,flags;public ushort show,cbReserved;public IntPtr reserved2,input,output,error;}
 [StructLayout(LayoutKind.Sequential)] struct StartupInfoEx {public StartupInfo startup;public IntPtr attributes;}
 [StructLayout(LayoutKind.Sequential)] struct ProcessInformation {public IntPtr process,thread;public uint pid,tid;}
 [StructLayout(LayoutKind.Sequential)] struct BasicLimits {public long processTime,jobTime;public uint flags;public UIntPtr min,max;public uint active;public UIntPtr affinity;public uint priority,scheduling;}
 [StructLayout(LayoutKind.Sequential)] struct IoCounters {public ulong reads,writes,others,readBytes,writeBytes,otherBytes;}
 [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits {public BasicLimits basic;public IoCounters io;public UIntPtr processMemory,jobMemory,peakProcessMemory,peakJobMemory;}
 [StructLayout(LayoutKind.Sequential)] struct CompletionPort {public IntPtr key,port;}
 [StructLayout(LayoutKind.Sequential)] struct BasicAccounting {public long user,kernel,periodUser,periodKernel;public uint faults,total,active,terminated;}
 [StructLayout(LayoutKind.Sequential)] struct SecurityCapabilities {public IntPtr sid,capabilities;public uint count,reserved;}
 [StructLayout(LayoutKind.Sequential)] struct FileInformation {public uint attributes,createdLow,createdHigh,accessedLow,accessedHigh,writtenLow,writtenHigh,volume,sizeHigh,sizeLow,links,indexHigh,indexLow;}
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode,EntryPoint="CreateFileW")] static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle file,out FileInformation info);
 [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int CreateAppContainerProfile(string name,string display,string description,IntPtr capabilities,uint count,out IntPtr sid);
 [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int DeleteAppContainerProfile(string name);
 [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int DeriveAppContainerSidFromAppContainerName(string name,out IntPtr sid);
 [DllImport("shell32.dll")] static extern int SHGetKnownFolderPath([MarshalAs(UnmanagedType.LPStruct)] Guid id,uint flags,IntPtr token,out IntPtr path);
 [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr data,int size,out int needed);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,IntPtr data,uint length);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,IntPtr data,uint length,out uint returned);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref IntPtr bytes);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
 [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode,EntryPoint="CreateProcessW")] static extern bool CreateProcess(string application,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string cwd,ref StartupInfoEx startup,out ProcessInformation process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out SafeFileHandle read,out SafeFileHandle write,ref SecurityAttributes attributes,uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetHandleInformation(SafeHandle handle,uint mask,uint flags);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,int milliseconds);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long creation,out long exit,out long kernel,out long user);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateIoCompletionPort(IntPtr file,IntPtr existing,UIntPtr key,uint threads);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetQueuedCompletionStatus(IntPtr port,out uint message,out UIntPtr key,out IntPtr payload,uint milliseconds);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool PostQueuedCompletionStatus(IntPtr port,uint bytes,UIntPtr key,IntPtr overlapped);
}
