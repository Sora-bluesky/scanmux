using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

// The owner constructs this context only from its verified immutable v2 intent.
internal sealed class RetainedContext {
 internal string directory, jobId, intentSha256;
 internal int maximum;
 internal long allocatedBytes, clusterBytes;
 internal RetainedAsset[] assets;
}
internal sealed class RetainedAsset {
 internal readonly string path,sha256;internal readonly long bytes;
 internal RetainedAsset(string path,long bytes,string sha256){this.path=path;this.bytes=bytes;this.sha256=sha256;}
}
internal sealed class RetainedPart { internal int slot; internal byte[] bytes; internal RetainedPart(int slot,byte[] bytes){this.slot=slot;this.bytes=bytes;} }
internal sealed class RetainedError:Exception {
 internal readonly string operation; internal readonly uint win32;
 internal RetainedError(string operation,uint win32):base(operation){this.operation=operation;this.win32=win32;}
}
internal sealed class RetainedSlot {
 public int slot; public string name; public int maximum; public bool reserved;
 internal RetainedSlot(int slot,string name,int maximum,bool reserved){this.slot=slot;this.name=name;this.maximum=maximum;this.reserved=reserved;}
}
internal sealed class RetainedFile { public int slot;public long bytes,allocatedBytes; }
internal sealed class RetainedSnapshot { public long allocatedBytes,reservedBytes,allocatedLimit,clusterBytes;public List<RetainedFile> files=new List<RetainedFile>(); }
internal sealed class RetainedResult {
 public string schema="scanmux.retained-write-result/v1",result,jobId,intentSha256;
 public int[] slots;public long proposedAllocatedBytes,availableIntermediateBytes;public RetainedSnapshot before,after;
}

internal sealed class RetainedStore:IDisposable {
 const long MaximumSafe=9007199254740991;
 const uint Read=0x80000000,Write=0x40000000,Attributes=0x80,OpenExisting=3,CreateNew=1;
 const uint Reparse=0x400,Sparse=0x200,Compressed=0x800,Encrypted=0x4000,DirectoryFlag=0x10;
 const string LockName="retained-write.lock";
 static readonly UTF8Encoding Utf8=new UTF8Encoding(false,true);
 static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=65536};
 readonly RetainedContext context;
 readonly RetainedSlot[] catalog;
 readonly List<SafeFileHandle> directories=new List<SafeFileHandle>();
 SafeFileHandle lockHandle;
 bool initialized,disposed;

 internal static RetainedSlot[] Catalog(int maximum){
  Require(maximum>0,"descriptor");var rows=new List<RetainedSlot>();
  Add(rows,"host-job-intent.json",65536,true);Add(rows,"host-job-failure.json",4096,true);Add(rows,"host-job-retained.json",4096,true);
  foreach(string name in new string[]{"owner.json","report.json","delegated-job.json","host-job-primary.json","host-job-cleanup.json","host-job-native.json","host-job.json"})Add(rows,name,maximum,true);
  Add(rows,"job-plan.json",maximum,false);
  for(int sequence=1;sequence<=4;sequence++){Add(rows,"checkpoints/checkpoint-"+sequence+".json",maximum,false);Add(rows,"checkpoints/commit-"+sequence+".json",maximum,false);}
  return rows.ToArray();
 }
 static void Add(List<RetainedSlot> rows,string name,int maximum,bool reserved){rows.Add(new RetainedSlot(rows.Count,name,maximum,reserved));}
 internal static void Require(bool value,string operation){if(!value)throw new RetainedError(operation,0);}
 static void Native(bool value,string operation){int error=Marshal.GetLastWin32Error();if(!value)throw new RetainedError(operation,unchecked((uint)error));}
 internal static string Hash(byte[] bytes){using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();}
 internal static string LocalPath(string input){
  Require(input!=null && input.Length>=3 && Char.IsLetter(input[0]) && input[1]==':' && (input[2]=='\\'||input[2]=='/') && input.Substring(2).IndexOf(':')<0 && input.IndexOfAny(new char[]{'\0','\r','\n'})<0,"path");
  string full=Path.GetFullPath(input);Require(full.Length>3 && !full.EndsWith("\\",StringComparison.Ordinal),"path");return full;
 }
 static bool Sha(string value){if(value==null||value.Length!=64)return false;foreach(char c in value)if(!(c>='0'&&c<='9'||c>='a'&&c<='f'))return false;return true;}
 static string ActualPath(SafeFileHandle handle){var text=new StringBuilder(32768);uint length=GetFinalPathNameByHandle(handle,text,(uint)text.Capacity,0);Native(length>0&&length<text.Capacity,"path");string full=text.ToString();Require(full.StartsWith("\\\\?\\",StringComparison.Ordinal),"path");return full.Substring(4);}
 static BasicInfo Identity(SafeFileHandle handle){BasicInfo value;Native(GetFileInformationByHandle(handle,out value),"identity");return value;}
 static StandardInfo Standard(SafeFileHandle handle){StandardInfo value;Native(GetStandard(handle,1,out value,(uint)Marshal.SizeOf(typeof(StandardInfo))),"accounting");return value;}
 static void Plain(BasicInfo info,bool directory){Require((info.attributes&(Reparse|Sparse|Compressed|Encrypted))==0 && ((info.attributes&DirectoryFlag)!=0)==directory,"attributes");if(!directory)Require(info.links==1,"identity");}
 static void Streams(SafeFileHandle handle,StandardInfo standard){
  const int capacity=65536;IntPtr buffer=Marshal.AllocHGlobal(capacity);
  try{
   if(!GetInformation(handle,7,buffer,capacity)){int error=Marshal.GetLastWin32Error();Require(error==38 && standard.eof==0 && standard.allocation==0,"streams");return;}
   int offset=0,count=0;
   for(;;){Require(offset>=0&&offset<=capacity-24,"streams");int next=Marshal.ReadInt32(buffer,offset),length=Marshal.ReadInt32(buffer,offset+4);Require(length>=0&&length%2==0&&length<=capacity-offset-24,"streams");
    string name=Marshal.PtrToStringUni(IntPtr.Add(buffer,offset+24),length/2);Require(name=="::$DATA" && ++count==1 && Marshal.ReadInt64(buffer,offset+8)==standard.eof && Marshal.ReadInt64(buffer,offset+16)==standard.allocation,"streams");
    if(next==0)break;Require(next>=24+length && next<=capacity-offset-24,"streams");offset=checked(offset+next);
   }
  }finally{Marshal.FreeHGlobal(buffer);}
 }
 SafeFileHandle Lease(string directory){
  // Attribute-only opens do not participate in the read/write/delete share check.
  SafeFileHandle handle=CreateFile(directory,Attributes|1,3,IntPtr.Zero,OpenExisting,0x02200000,IntPtr.Zero);Native(!handle.IsInvalid,"directory");
  try{Plain(Identity(handle),true);Require(String.Equals(ActualPath(handle),directory,StringComparison.OrdinalIgnoreCase),"path");directories.Add(handle);return handle;}catch{handle.Dispose();throw;}
 }
 static SafeFileHandle OpenFile(string file,uint access,uint disposition,uint share){
  SafeFileHandle handle=CreateFile(file,access,share,IntPtr.Zero,disposition,0x80200080,IntPtr.Zero);Native(!handle.IsInvalid,"open");
  try{Plain(Identity(handle),false);Require(String.Equals(ActualPath(handle),file,StringComparison.OrdinalIgnoreCase),"path");StandardInfo s=Standard(handle);Require(s.directory==0&&s.deleted==0,"identity");Streams(handle,s);return handle;}catch{handle.Dispose();throw;}
 }
 internal static object Probe(string directory){
  directory=LocalPath(directory);uint sectors,bytes,free,total,serial,maximum,flags;var fs=new StringBuilder(32);var label=new StringBuilder(261);
  Native(GetDiskFreeSpace(Path.GetPathRoot(directory),out sectors,out bytes,out free,out total),"geometry");Native(GetVolumeInformation(Path.GetPathRoot(directory),label,(uint)label.Capacity,out serial,out maximum,out flags,fs,(uint)fs.Capacity),"geometry");
  long cluster=checked((long)sectors*bytes);Require(fs.ToString()=="NTFS"&&cluster>0&&cluster<=MaximumSafe,"geometry");return Obj("schema","scanmux.retained-volume/v1","fileSystem","NTFS","clusterBytes",cluster);
 }
 internal static long Cluster(string directory){return (long)((Dictionary<string,object>)Probe(directory))["clusterBytes"];}
 internal static Dictionary<string,object> DirectoryIdentity(string directory){
  directory=LocalPath(directory);using(var handle=CreateFile(directory,Attributes|1,3,IntPtr.Zero,OpenExisting,0x02200000,IntPtr.Zero)){
   Native(!handle.IsInvalid,"directory");var info=Identity(handle);Plain(info,true);Require(String.Equals(ActualPath(handle),directory,StringComparison.OrdinalIgnoreCase),"path");
   ulong modified=((ulong)info.writtenHigh<<32)|info.writtenLow;Require(modified>=116444736000000000UL,"identity");
   return Obj("device",info.volume.ToString(CultureInfo.InvariantCulture),"inode",(((ulong)info.indexHigh<<32)|info.indexLow).ToString(CultureInfo.InvariantCulture),"modifiedNs",checked((modified-116444736000000000UL)*100UL).ToString(CultureInfo.InvariantCulture));
  }
 }
 long Round(long n){Require(n>=0&&n<=MaximumSafe,"accounting");long value=checked((checked(n+context.clusterBytes-1)/context.clusterBytes)*context.clusterBytes);Require(value<=MaximumSafe,"accounting");return value;}
 static long Sum(long a,long b){long value=checked(a+b);Require(value>=0&&value<=MaximumSafe,"accounting");return value;}
 string Name(RetainedSlot slot){return Path.Combine(context.directory,slot.name.Replace('/',Path.DirectorySeparatorChar));}

 internal RetainedStore(RetainedContext supplied,bool initialize){
  Require(supplied!=null&&supplied.maximum>0&&supplied.assets!=null&&Sha(supplied.intentSha256),"descriptor");Guid id;Require(Guid.TryParseExact(supplied.jobId,"D",out id)&&id.ToString()==supplied.jobId,"descriptor");
  context=new RetainedContext{directory=LocalPath(supplied.directory),jobId=supplied.jobId,intentSha256=supplied.intentSha256,maximum=supplied.maximum,allocatedBytes=supplied.allocatedBytes,clusterBytes=supplied.clusterBytes,assets=(RetainedAsset[])supplied.assets.Clone()};
  catalog=Catalog(context.maximum);Require(context.clusterBytes==Cluster(context.directory)&&context.allocatedBytes>0&&context.allocatedBytes<=MaximumSafe&&context.allocatedBytes%context.clusterBytes==0,"geometry");
  long minimum=0;foreach(var slot in catalog)if(slot.reserved)minimum=Sum(minimum,Round(slot.maximum));Require(minimum<=context.allocatedBytes,"reserve");
  try{
   Lease(context.directory);lockHandle=OpenFile(Path.Combine(context.directory,LockName),Read|Write,initialize?CreateNew:OpenExisting,0);StandardInfo locked=Standard(lockHandle);Require(locked.eof==0&&locked.allocation==0,"lock");
   if(!initialize){byte[] intent=ReadRecord(catalog[0]);Require(intent.Length>0&&Hash(intent)==context.intentSha256,"intent");initialized=true;}
   RetainedSnapshot state=Inspect();if(initialize)Require(state.files.Count==0,"initialization");
  }catch{Dispose();throw;}
 }
 byte[] ReadRecord(RetainedSlot slot){
  using(var handle=OpenFile(Name(slot),Read,OpenExisting,1))using(var file=new FileStream(handle,FileAccess.Read,4096,false)){
   StandardInfo info=Standard(handle);Require(info.eof>=0&&info.eof<=slot.maximum,"accounting");byte[] bytes=new byte[(int)info.eof];ReadExact(file,bytes);Require(file.ReadByte()==-1,"read");return bytes;
  }
 }
 static void ReadExact(Stream input,byte[] bytes){int used=0,read;while(used<bytes.Length&&(read=input.Read(bytes,used,bytes.Length-used))>0)used+=read;Require(used==bytes.Length,"read");}
 void EmptyFile(string file){using(var handle=OpenFile(file,Read,OpenExisting,1)){StandardInfo info=Standard(handle);Require(info.eof==0&&info.allocation==0,"infrastructure");}}
 void EmptyDirectory(string directory){Lease(directory);Require(Directory.GetFileSystemEntries(directory).Length==0,"infrastructure");}
 void Application(string application){
  Lease(application);var expected=new Dictionary<string,RetainedAsset>(StringComparer.Ordinal);var allowedDirectories=new HashSet<string>(StringComparer.Ordinal){application};
  foreach(var asset in context.assets){Require(asset!=null&&asset.path!=null&&asset.bytes>0&&Sha(asset.sha256)&&asset.path.IndexOfAny(new char[]{'\\',':','\0','\r','\n'})<0&&!Path.IsPathRooted(asset.path),"asset");string full=Path.GetFullPath(Path.Combine(application,asset.path.Replace('/',Path.DirectorySeparatorChar)));Require(full.StartsWith(application+"\\",StringComparison.Ordinal)&&!expected.ContainsKey(full),"asset");expected.Add(full,asset);for(string parent=Path.GetDirectoryName(full);parent!=application;parent=Path.GetDirectoryName(parent)){Require(parent!=null&&parent.StartsWith(application+"\\",StringComparison.Ordinal),"asset");allowedDirectories.Add(parent);}}
  var todo=new Stack<string>();todo.Push(application);int observed=0;
  while(todo.Count>0){string directory=todo.Pop();foreach(string entry in Directory.GetFileSystemEntries(directory)){
   FileAttributes attrs=File.GetAttributes(entry);if((attrs&FileAttributes.Directory)!=0){Require(allowedDirectories.Contains(entry),"asset");Lease(entry);todo.Push(entry);continue;}
   RetainedAsset asset;Require(expected.TryGetValue(entry,out asset),"asset");using(var handle=OpenFile(entry,Read,OpenExisting,1))using(var file=new FileStream(handle,FileAccess.Read,65536,false))using(var sha=SHA256.Create()){Require(Standard(handle).eof==asset.bytes,"asset");string actual=BitConverter.ToString(sha.ComputeHash(file)).Replace("-","").ToLowerInvariant();Require(actual==asset.sha256,"asset");}observed++;
  }}Require(observed==expected.Count,"asset");
 }
 internal RetainedSnapshot Inspect(){
  Require(!disposed,"lifetime");var present=new HashSet<string>(StringComparer.Ordinal);
  foreach(string entry in Directory.GetFileSystemEntries(context.directory)){
   string name=Path.GetFileName(entry);FileAttributes attrs=File.GetAttributes(entry);
   if((attrs&FileAttributes.Directory)!=0){
    if(name=="checkpoints"){Lease(entry);foreach(string child in Directory.GetFileSystemEntries(entry)){string relative="checkpoints/"+Path.GetFileName(child);Require(Array.Exists(catalog,s=>s.name==relative),"catalog");present.Add(relative);}continue;}
    if(name=="app"){Application(entry);continue;}
    if(name=="docker-config"||name=="host-cleanup-docker-config"){EmptyDirectory(entry);continue;}
    if(name=="AppData"){Lease(entry);string roaming=Path.Combine(entry,"Roaming");string[] children=Directory.GetFileSystemEntries(entry);Require(children.Length==1&&children[0]==roaming,"infrastructure");EmptyDirectory(roaming);continue;}
    throw new RetainedError("catalog",0);
   }
   if(name==LockName){Require(lockHandle!=null&&!lockHandle.IsInvalid,"lock");continue;}
   if(name=="empty-gitconfig"){EmptyFile(entry);continue;}
   Require(Array.Exists(catalog,s=>s.name==name),"catalog");present.Add(name);
  }
  var state=new RetainedSnapshot{allocatedLimit=context.allocatedBytes,clusterBytes=context.clusterBytes};
  foreach(var slot in catalog){if(present.Contains(slot.name)){
   using(var handle=OpenFile(Name(slot),Read,OpenExisting,1)){StandardInfo info=Standard(handle);Require(info.eof>=0&&info.eof<=slot.maximum&&info.allocation==Round(info.eof),"accounting");state.files.Add(new RetainedFile{slot=slot.slot,bytes=info.eof,allocatedBytes=info.allocation});state.allocatedBytes=Sum(state.allocatedBytes,info.allocation);}
  }else if(slot.reserved)state.reservedBytes=Sum(state.reservedBytes,Round(slot.maximum));}
  Require(Sum(state.allocatedBytes,state.reservedBytes)<=context.allocatedBytes,"accounting");return state;
 }
 void Validate(RetainedPart[] parts,bool initialize){
  Require(parts!=null&&parts.Length>=1&&parts.Length<=2,"request");foreach(var part in parts)Require(part!=null&&part.slot>=0&&part.slot<catalog.Length&&part.bytes!=null&&part.bytes.Length>0&&part.bytes.Length<=catalog[part.slot].maximum,"request");
  if(initialize){Require(!initialized&&parts.Length==1&&parts[0].slot==0&&Hash(parts[0].bytes)==context.intentSha256,"initialization");return;}
  Require(initialized&&parts[0].slot!=0&&parts[0].slot!=2,"request");if(parts.Length==1)Require(parts[0].slot<=10,"request");else Require(parts[0].slot>=11&&(parts[0].slot-11)%2==0&&parts[1].slot==parts[0].slot+1,"request");
 }
 void MappedWrite(RetainedPart part){
  var slot=catalog[part.slot];string file=Name(slot);if(slot.name.StartsWith("checkpoints/",StringComparison.Ordinal)){string checkpoint=Path.Combine(context.directory,"checkpoints");if(!Directory.Exists(checkpoint))Directory.CreateDirectory(checkpoint);Lease(checkpoint);}
  using(var handle=OpenFile(file,Read|Write,CreateNew,1))using(var output=new FileStream(handle,FileAccess.ReadWrite,4096,false)){
   BasicInfo initial=Identity(handle);var allocation=new AllocationInfo{size=Round(part.bytes.Length)};Native(SetAllocation(handle,5,ref allocation,8),"allocate");
   var eof=new AllocationInfo{size=part.bytes.Length};Native(SetAllocation(handle,6,ref eof,8),"eof");StandardInfo before=Standard(handle);Require(before.allocation==allocation.size&&before.eof==part.bytes.Length,"accounting");
   using(var mapping=MemoryMappedFile.CreateFromFile(output,null,part.bytes.Length,MemoryMappedFileAccess.ReadWrite,HandleInheritability.None,true))using(var view=mapping.CreateViewAccessor(0,part.bytes.Length,MemoryMappedFileAccess.ReadWrite)){view.WriteArray(0,part.bytes,0,part.bytes.Length);view.Flush();output.Flush(true);}
   StandardInfo after=Standard(handle);BasicInfo identity=Identity(handle);Require(after.allocation==allocation.size&&after.eof==part.bytes.Length&&after.deleted==0&&identity.volume==initial.volume&&identity.indexHigh==initial.indexHigh&&identity.indexLow==initial.indexLow,"identity");Plain(identity,false);Streams(handle,after);
   output.Position=0;using(var sha=SHA256.Create()){string actual=BitConverter.ToString(sha.ComputeHash(output)).Replace("-","").ToLowerInvariant();Require(actual==Hash(part.bytes),"hash");}
  }
 }
 internal RetainedResult WriteBatch(RetainedPart[] parts,bool initialize){
  Validate(parts,initialize);RetainedSnapshot before=Inspect();long proposed=0,released=0;var slots=new int[parts.Length];
  if(before.files.Exists(f=>f.slot==2))foreach(var part in parts)Require(catalog[part.slot].reserved,"closed");
  for(int i=0;i<parts.Length;i++){var part=parts[i];Require(!before.files.Exists(f=>f.slot==part.slot),"occupied");proposed=Sum(proposed,Round(part.bytes.Length));if(catalog[part.slot].reserved)released=Sum(released,Round(catalog[part.slot].maximum));slots[i]=part.slot;}
  long reservations=checked(before.reservedBytes-released),available=checked(context.allocatedBytes-before.allocatedBytes-reservations);
  if(proposed>available){
   Require(!initialize&&released==0&&!before.files.Exists(f=>f.slot==2),"reserve");
   var details=new List<object>();foreach(var part in parts)details.Add(Obj("slot",part.slot,"bytes",part.bytes.Length));
   byte[] witness=Utf8.GetBytes(Json.Serialize(Obj("schema","scanmux.retained-allocation-stop/v1","jobId",context.jobId,"intentSha256",context.intentSha256,"parts",details,"proposedAllocatedBytes",proposed,"availableIntermediateBytes",available,"actualAllocatedBytes",before.allocatedBytes,"reservedBytes",before.reservedBytes,"allocatedLimit",context.allocatedBytes,"clusterBytes",context.clusterBytes))+"\n");
   Require(witness.Length<=catalog[2].maximum,"reserve");MappedWrite(new RetainedPart(2,witness));
   return new RetainedResult{result="retained_allocated_limit",jobId=context.jobId,intentSha256=context.intentSha256,slots=slots,proposedAllocatedBytes=proposed,availableIntermediateBytes=available,before=before,after=Inspect()};
  }
  foreach(var part in parts)MappedWrite(part);if(initialize)initialized=true;RetainedSnapshot after=Inspect();
  Require(after.allocatedBytes==Sum(before.allocatedBytes,proposed),"accounting");
  return new RetainedResult{result="committed",jobId=context.jobId,intentSha256=context.intentSha256,slots=slots,proposedAllocatedBytes=proposed,availableIntermediateBytes=available,before=before,after=after};
 }
 internal static RetainedPart[] Decode(Stream input,int maximum){
  var line=new List<byte>();for(;;){int value=input.ReadByte();Require(value>=0,"request");if(value==10)break;Require(value>=32&&value<=126&&line.Count<4095,"request");line.Add((byte)value);}
  var header=Map(Json.DeserializeObject(Encoding.ASCII.GetString(line.ToArray())));Keys(header,"schema","kind","sequence","parts");Require((string)header["schema"]=="scanmux.retained-write-request/v1","request");
  string kind=Text(header["kind"]);int sequence=Int(header["sequence"],0,4);var descriptions=header["parts"] as object[];Require(descriptions!=null&&descriptions.Length>=1&&descriptions.Length<=2,"request");var parts=new List<RetainedPart>();var catalog=Catalog(maximum);
  var canonicalParts=new List<object>();
  foreach(var raw in descriptions){var item=Map(raw);Keys(item,"slot","bytes","sha256");int slot=Int(item["slot"],1,18);Require(slot!=2,"request");int bytes=Int(item["bytes"],1,catalog[slot].maximum);string sha=Text(item["sha256"]);Require(Sha(sha),"request");canonicalParts.Add(Obj("slot",slot,"bytes",bytes,"sha256",sha));byte[] value=new byte[bytes];ReadExact(input,value);Require(Hash(value)==sha,"hash");parts.Add(new RetainedPart(slot,value));}
  Require(Encoding.ASCII.GetString(line.ToArray())==Json.Serialize(Obj("schema","scanmux.retained-write-request/v1","kind",kind,"sequence",sequence,"parts",canonicalParts)),"request");
  Require(input.ReadByte()==-1,"request");if(kind=="single")Require(sequence==0&&parts.Count==1&&parts[0].slot<=10,"request");else Require(kind=="checkpoint"&&sequence>=1&&parts.Count==2&&parts[0].slot==11+2*(sequence-1)&&parts[1].slot==parts[0].slot+1,"request");return parts.ToArray();
 }
 static Dictionary<string,object> Map(object value){var result=value as Dictionary<string,object>;Require(result!=null,"request");return result;}
 static void Keys(Dictionary<string,object> value,params string[] keys){Require(value.Count==keys.Length,"request");foreach(string key in keys)Require(value.ContainsKey(key),"request");}
 static string Text(object value){Require(value is string,"request");return (string)value;}
 static int Int(object value,int minimum,int maximum){Require(value is int,"request");int n=(int)value;Require(n>=minimum&&n<=maximum,"request");return n;}
 internal static Dictionary<string,object> Obj(params object[] pairs){var result=new Dictionary<string,object>();for(int i=0;i<pairs.Length;i+=2)result.Add((string)pairs[i],pairs[i+1]);return result;}
 public void Dispose(){if(disposed)return;disposed=true;if(lockHandle!=null)lockHandle.Dispose();for(int i=directories.Count-1;i>=0;i--)directories[i].Dispose();directories.Clear();}

 [StructLayout(LayoutKind.Sequential)]struct StandardInfo{public long allocation,eof;public uint links;public byte deleted,directory;}
 [StructLayout(LayoutKind.Sequential)]struct AllocationInfo{public long size;}
 [StructLayout(LayoutKind.Sequential)]struct BasicInfo{public uint attributes,createdLow,createdHigh,accessLow,accessHigh,writtenLow,writtenHigh,volume,sizeHigh,sizeLow,links,indexHigh,indexLow;}
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode,EntryPoint="CreateFileW")]static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle handle,out BasicInfo value);
 [DllImport("kernel32.dll",SetLastError=true,EntryPoint="GetFileInformationByHandleEx")]static extern bool GetStandard(SafeFileHandle handle,int kind,out StandardInfo value,uint size);
 [DllImport("kernel32.dll",SetLastError=true,EntryPoint="GetFileInformationByHandleEx")]static extern bool GetInformation(SafeFileHandle handle,int kind,IntPtr buffer,int size);
 [DllImport("kernel32.dll",SetLastError=true,EntryPoint="SetFileInformationByHandle")]static extern bool SetAllocation(SafeFileHandle handle,int kind,ref AllocationInfo value,uint size);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder path,uint size,uint flags);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode,EntryPoint="GetDiskFreeSpaceW")]static extern bool GetDiskFreeSpace(string root,out uint sectors,out uint bytes,out uint free,out uint total);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode,EntryPoint="GetVolumeInformationW")]static extern bool GetVolumeInformation(string root,StringBuilder label,uint labelSize,out uint serial,out uint maximum,out uint flags,StringBuilder fileSystem,uint fileSystemSize);
}
