"""Fixed, unprivileged Linux/x64 job owner. Target data never selects commands."""
import base64
import ctypes as C
import errno
import hashlib
import json
import os
import select
import signal
import stat
import sys
import time

LIB = C.CDLL(None, use_errno=True)
LIB.ptrace.restype = C.c_long
LIB.ptrace.argtypes = [C.c_ulong, C.c_ulong, C.c_void_p, C.c_void_p]
SEIZE, INTERRUPT, GETINFO, GETEVENT, CONT, SYSCALL = 0x4206, 0x4207, 0x420e, 0x4201, 7, 24
OPTIONS = 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128 | 0x100000
WAITALL, ARCH = 0x40000000, 0xc000003e
START = time.monotonic()
MAX_INTEGER = 9007199254740991
OPERATIONS = {'require', 'exact', 'integer', 'read_small', 'file_hash', 'ptrace', 'syscall_info', 'event_message', 'security',
              'restrict_child', 'counters', 'network', 'mount_info', 'safe_root_probe', 'boundary', 'verify_assets', 'verify_source_types',
              'emit', 'host_packet', 'service', 'add', 'resume', 'wait', 'ingest', 'all_stop', 'observe', 'step', 'launch', 'kill_reap', 'close', 'main'}


class Invalid(Exception):
    def __init__(self, native_errno=None):
        frame = sys._getframe(1)
        if frame.f_code.co_name == 'require':
            frame = frame.f_back
        self.detail = {'kind': 'invariant', 'operation': frame.f_code.co_name if frame.f_code.co_name in OPERATIONS else 'unknown',
                       'site': frame.f_lineno, 'errno': native_errno}
        super().__init__()


class Stopping(Exception):
    pass


def require(value):
    if not value:
        raise Invalid()


def exact(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys))
    return value


def reproduction_operation(value):
    exact(value, ['kind', 'side', 'commit', 'sourceSnapshot', 'finding', 'sourceReportSha256', 'testDirectory', 'mode', 'expectedTest'])
    require(value['kind'] == 'reproduction' and value['side'] in ['snapshot', 'before', 'after'])
    def hex_value(item, length):
        require(type(item) is str and len(item) == length and all(character in '0123456789abcdef' for character in item))
    hex_value(value['commit'], 40)
    snapshot = exact(value['sourceSnapshot'], ['commit', 'tree', 'snapshotHash'])
    hex_value(snapshot['commit'], 40); hex_value(snapshot['tree'], 40); hex_value(snapshot['snapshotHash'], 64)
    finding = exact(value['finding'], ['engine', 'fingerprint'])
    require(finding['engine'] in ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'])
    hex_value(finding['fingerprint'], 64); hex_value(value['sourceReportSha256'], 64)
    directory = value['testDirectory']
    require(type(directory) is str and 0 < len(directory) <= 1024 and not directory.startswith('/') and ':' not in directory and '\\' not in directory
            and all(ord(character) >= 32 and ord(character) != 127 for character in directory)
            and all(part not in ['', '.', '..'] and part.lower() != '.git' for part in directory.split('/')))
    mode = value['mode']
    if isinstance(mode, dict) and mode.get('kind') == 'snapshot':
        exact(mode, ['kind', 'requirement'])
        require(mode['requirement'] in ['supporting', 'required'] and value['side'] == 'snapshot' and value['commit'] == snapshot['commit'])
    else:
        exact(mode, ['kind', 'base', 'head'])
        hex_value(mode['base'], 40); hex_value(mode['head'], 40)
        require(mode['kind'] == 'before_after' and mode['base'] != mode['head'] and snapshot['commit'] == mode['base'] and value['side'] in ['before', 'after']
                and value['commit'] == mode['head' if value['side'] == 'after' else 'base'])
    require(value['expectedTest'] is None or type(value['expectedTest']) is dict)
    require(value['side'] != 'after' or value['expectedTest'] is not None)


def integer(value, positive=False):
    require(type(value) is int and (1 if positive else 0) <= value <= MAX_INTEGER)
    return value


def read_small(file, maximum=16384):
    with open(file, 'rb') as source:
        value = source.read(maximum + 1)
    require(len(value) <= maximum)
    return value.decode('utf-8', errors='strict').strip()


def file_hash(file):
    value = hashlib.sha256()
    with open(file, 'rb') as source:
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            value.update(chunk)
    return value.hexdigest()


def ptrace(op, tid, address=0, data=0):
    C.set_errno(0)
    pointer = C.cast(data, C.c_void_p) if not isinstance(data, int) else C.c_void_p(data)
    result = LIB.ptrace(op, tid, C.c_void_p(address), pointer)
    if result == -1 and C.get_errno():
        raise Invalid(C.get_errno())
    return result


def syscall_info(tid):
    raw = C.create_string_buffer(128)
    count = ptrace(GETINFO, tid, len(raw), C.byref(raw))
    data = raw.raw
    op = data[0]
    require(count >= {1: 80, 2: 33, 3: 84}.get(op, 129))
    require(int.from_bytes(data[4:8], 'little') == ARCH)
    if op == 2:
        return {'op': op, 'rval': int.from_bytes(data[24:32], 'little', signed=True), 'isError': bool(data[32])}
    return {'op': op, 'nr': int.from_bytes(data[24:32], 'little'),
            'args': [int.from_bytes(data[i:i+8], 'little') for i in range(32, 80, 8)]}


def event_message(tid):
    result = C.c_ulonglong()
    ptrace(GETEVENT, tid, 0, C.byref(result))
    return result.value


def security(tid='self'):
    fields = dict(line.split(':', 1) for line in read_small('/proc/%s/status' % tid).splitlines() if ':' in line)
    for name in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
        require(int(fields[name].strip(), 16) == 0)
    require(fields['NoNewPrivs'].strip() == '1' and fields['Seccomp'].strip() == '2')
    return int(fields['Seccomp_filters'].strip())


class Filter(C.Structure):
    _fields_ = [('code', C.c_ushort), ('jt', C.c_ubyte), ('jf', C.c_ubyte), ('k', C.c_uint)]


class Program(C.Structure):
    _fields_ = [('len', C.c_ushort), ('filter', C.POINTER(Filter))]


def restrict_child():
    instructions = [(0x20, 0, 0, 4), (0x15, 1, 0, ARCH), (0x06, 0, 0, 0x80000000),
                    (0x20, 0, 0, 0), (0x45, 0, 1, 0x40000000), (0x06, 0, 0, 0x80000000)]
    for number in [101, 310, 311, 272, 308, 425, 426, 427, 319, 447]:
        instructions.extend([(0x15, 0, 1, number), (0x06, 0, 0, 0x50001)])
    # clone3 falls back to legacy clone, whose flag argument is checked below.
    instructions.extend([(0x15, 0, 1, 435), (0x06, 0, 0, 0x50026)])
    # CLONE_UNTRACED and every namespace flag would invalidate the owned population.
    forbidden = 0x00800000 | 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000
    instructions.extend([(0x15, 0, 4, 56), (0x20, 0, 0, 16), (0x45, 0, 1, forbidden),
                         (0x06, 0, 0, 0x50001), (0x06, 0, 0, 0x7fff0000)])
    for number in [1, 18]:
        instructions.extend([(0x15, 0, 1, number), (0x06, 0, 0, 0x7ff00000)])
    instructions.append((0x06, 0, 0, 0x7fff0000))
    array = (Filter * len(instructions))(*(Filter(*row) for row in instructions))
    program = Program(len(instructions), array)
    require(LIB.prctl(38, 1, 0, 0, 0) == 0 and LIB.prctl(22, 2, C.byref(program), 0, 0) == 0)


def counters(file):
    result = {}
    for row in read_small(file).splitlines():
        key, value = row.split()
        require(key not in result)
        result[key] = integer(int(value))
    return result


def network():
    rows = read_small('/proc/net/dev').splitlines()[2:]
    require(len(rows) == 1 and rows[0].split(':')[0].strip() == 'lo')
    values = [integer(int(value)) for value in rows[0].split(':')[1].split()]
    require(len(values) == 16 and len(read_small('/proc/net/route').splitlines()) == 1)
    return values


def mount_info():
    result = {}
    for row in read_small('/proc/self/mountinfo', 65536).splitlines():
        before, after = row.split(' - ')
        columns, filesystem = before.split(), after.split()
        destination = columns[4]
        # Fixed payload destinations contain no escaped mountinfo characters.
        require(destination not in result)
        result[destination] = {'options': columns[5].split(','), 'type': filesystem[0]}
    return result


def safe_root_probe(folder, nonce):
    file = folder.rstrip('/') + '/.scanmux-job-' + nonce
    try:
        descriptor = os.open(file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as error:
        require(error.errno in [errno.EACCES, errno.EROFS, errno.EPERM])
        return
    # Only an unexpectedly created, exact owned probe is removable.
    created = os.fstat(descriptor)
    os.close(descriptor)
    found = os.lstat(file)
    require((created.st_dev, created.st_ino) == (found.st_dev, found.st_ino) and stat.S_ISREG(found.st_mode) and found.st_nlink == 1)
    os.unlink(file)
    raise Invalid()


def boundary(init, protection_verified):
    limits = init['limits']
    require(os.getpid() == 1 and os.getuid() == 1000 and os.getgid() == 1000 and set(os.getgroups()).issubset({1000}))
    security()
    require(LIB.prctl(3, 0, 0, 0, 0) == 0)  # PR_GET_DUMPABLE
    require(read_small('/proc/self/cgroup') == '0::/')
    cpu = [int(value) for value in read_small('/sys/fs/cgroup/cpu.max').split()]
    require(cpu == [limits['cpuCount'] * 100000, 100000])
    kernel = {'cpuQuota': cpu[0], 'cpuPeriod': cpu[1], 'memoryMax': int(read_small('/sys/fs/cgroup/memory.max')),
              'swapMax': int(read_small('/sys/fs/cgroup/memory.swap.max'))}
    require(kernel['memoryMax'] == limits['memoryBytes'] and kernel['swapMax'] == 0)
    require(int(read_small('/sys/fs/cgroup/pids.max')) == limits['pids'])
    mounts = mount_info()
    require('ro' in mounts['/']['options'])
    destinations = ['/app', init['expected']['mappedRoot'], '/tools/gitleaks']
    if 'osv' in init['expected']['config']['tools']:
        destinations.append('/tools/osv')
    destinations += [item['destination'] for item in init['database']]
    for destination in destinations:
        require(destination in mounts and 'ro' in mounts[destination]['options'])
    for folder, key in [('/tmp', 'tmpBytes'), ('/work', 'workBytes'), ('/dev/shm', 'shmBytes')]:
        require(mounts[folder]['type'] == 'tmpfs' and all(option in mounts[folder]['options'] for option in ['rw', 'noexec', 'nosuid', 'nodev']))
        values = os.statvfs(folder)
        kernel[key] = values.f_blocks * values.f_frsize
        require(values.f_frsize == 4096 and kernel[key] == limits[key])
    for destination, item in mounts.items():
        if 'rw' not in item['options'] or destination in ['/tmp', '/work', '/dev/shm']:
            continue
        if item['type'] in ['proc', 'sysfs', 'cgroup2', 'devpts', 'mqueue']:
            continue
        found = os.stat(destination)
        require(item['type'] == 'tmpfs' and (stat.S_ISCHR(found.st_mode) or not os.access(destination, os.W_OK, effective_ids=True)))
    for folder in ['/', '/dev', '/etc']:
        safe_root_probe(folder, init['nonce'])
    for file in ['/etc/hosts', '/etc/hostname', '/etc/resolv.conf']:
        require(not os.access(file, os.W_OK, effective_ids=True))
    memory = counters('/sys/fs/cgroup/memory.events')
    return {'kernel': kernel, 'pidsMax': limits['pids'], 'uid': 1000, 'gid': 1000, 'capabilitiesZero': True,
            'noNewPrivileges': True, 'seccomp': 2, 'supervisorNonDumpable': True, 'childSupervisorAccessDenied': protection_verified,
            'rootReadonly': True, 'boundedWritableStoresOnly': True, 'privateNamespaces': True,
            'networkCounters': network(), 'cpuThrottledPeriods': counters('/sys/fs/cgroup/cpu.stat')['nr_throttled'], 'oomKills': memory['oom_kill']}


def verify_assets(init):
    runtime = init['expected']['runtime']
    require('.'.join(str(value) for value in sys.version_info[:3]) == runtime['python']['version'])
    for item in [runtime['python'], runtime['git']] + list(runtime['tools'].values()):
        require(file_hash(item['path']) == item['sha256'])
    for item in runtime['app']:
        file = '/app/' + item['path']
        require(os.stat(file).st_size == item['bytes'] and file_hash(file) == item['sha256'])
    for item in init['database']:
        require(os.stat(item['destination']).st_size == item['bytes'] and file_hash(item['destination']) == item['sha256'])
    admitted = {item['destination'] for item in init['database']}
    parents = {'/db'}
    for file in admitted:
        parent = os.path.dirname(file)
        while parent != '/':
            parents.add(parent)
            parent = os.path.dirname(parent)
    if os.path.lexists('/db'):
        for directory, directories, files in os.walk('/db', followlinks=False):
            require(directory in parents and all(os.path.join(directory, name) in parents for name in directories)
                    and all(os.path.join(directory, name) in admitted for name in files))
    require(all(os.path.isfile(file) for file in admitted))


def verify_source_types(pump):
    # A readonly bind does not disable connection to a host UNIX socket or a device.
    # Inspect types only; Git and accepted blob contents remain the controller's work.
    pending = [os.scandir(pump.init['expected']['mappedRoot'])]
    try:
        while pending:
            pump.service()
            try:
                entry = next(pending[-1])
            except StopIteration:
                pending.pop().close()
                continue
            found = entry.stat(follow_symlinks=False)
            require(stat.S_ISREG(found.st_mode) or stat.S_ISDIR(found.st_mode) or stat.S_ISLNK(found.st_mode))
            if stat.S_ISDIR(found.st_mode):
                pending.append(os.scandir(entry.path))
    finally:
        for iterator in pending:
            iterator.close()


class Pump:
    def __init__(self, nonce, wall_ms, maximum):
        self.nonce, self.maximum = nonce, maximum
        self.deadline = START + wall_ms / 1000
        self.cleanup_deadline = None
        self.output = bytearray()
        self.input = bytearray()
        self.child_input = bytearray()
        self.sequence, self.host_sequence = 0, 0
        self.host_bytes = 0
        self.disk_samples = 0
        self.child_out = self.child_err = self.child_in = self.probe = None
        self.attachable = self.protection = False
        self.initialized = self.admitted = self.cleanup = self.host_eof = False
        self.init = None
        self.ready_sample = None
        self.stop_event = None
        self.stop_reason = None
        self.stderr_bytes = self.child_bytes = 0
        self.max_output_queue = 2 * (1024 + 4 * ((min(16384, maximum) + 2) // 3))
        self.max_control_line = max(65536, 1024 + 4 * ((min(16384, maximum) + 2) // 3))
        os.set_blocking(0, False)
        os.set_blocking(1, False)

    def emit(self, kind, **fields):
        packet = {'v': 1, 'nonce': self.nonce, 'seq': self.sequence + 1, 'type': kind, **fields}
        encoded = json.dumps(packet, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'
        require(len(encoded) <= self.max_control_line and len(self.output) + len(encoded) <= self.max_output_queue)
        self.sequence += 1
        self.output.extend(encoded)

    def initiate(self, reason, event=None):
        if self.stop_reason is None:
            self.stop_reason, self.stop_event = reason, event
            if event is not None:
                self.emit('stop', event=event)
        raise Stopping()

    def host_packet(self, line):
        value = json.loads(line.decode('utf-8', errors='strict'))
        require(type(value) is dict and value.get('v') == 1 and value.get('nonce') == self.nonce and value.get('seq') == self.host_sequence + 1)
        self.host_sequence += 1
        # init/start, six durable record ACKs, seven distinct failure ACKs, one stop.
        require(self.host_sequence <= 1 + 1 + 6 + 7 + 1 + getattr(self, 'disk_samples', 0) + (1 if getattr(self, 'disk_samples', 0) else 0))
        kind = value.get('type')
        if kind == 'init':
            exact(value, ['v', 'nonce', 'seq', 'type', 'payload'])
            require(not self.initialized)
            payload = value['payload']
            data = exact(payload, ['expected', 'limits', 'database']
                         + (['operation'] if isinstance(payload, dict) and 'operation' in payload else [])
                         + (['copyBudgetBytes'] if isinstance(payload, dict) and 'copyBudgetBytes' in payload else [])
                         + (['maxJobDiskBytes'] if isinstance(payload, dict) and 'maxJobDiskBytes' in payload else []))
            if 'operation' in data:
                reproduction_operation(data['operation'])
            if 'copyBudgetBytes' in data:
                integer(data['copyBudgetBytes'])
            if 'maxJobDiskBytes' in data:
                integer(data['maxJobDiskBytes'], True)
            limits = exact(data['limits'], ['cpuCount', 'memoryBytes', 'tmpBytes', 'workBytes', 'shmBytes', 'pids', 'wallMs', 'cleanupTimeoutMs', 'retainedBytes'])
            for item in limits.values():
                integer(item, True)
            require(limits['wallMs'] <= 2147483647 and limits['cleanupTimeoutMs'] <= 2147483647 and data['expected']['jobId'] == self.nonce)
            require(data['expected']['config']['maxOutputBytes'] == self.maximum)
            self.disk_samples = (limits['wallMs'] + limits['cleanupTimeoutMs'] + 99) // 100 + 8 if 'maxJobDiskBytes' in data else 0
            self.init = {**data, 'nonce': self.nonce}
            self.initialized = True
        elif kind == 'start':
            exact(value, ['v', 'nonce', 'seq', 'type', 'remainingMs'])
            require(self.initialized and self.protection and not self.admitted and self.ready_sample is not None)
            remaining = integer(value['remainingMs'], True)
            require(remaining <= self.init['limits']['wallMs'])
            self.deadline = min(self.deadline, self.ready_sample + remaining / 1000)
            require(time.monotonic() < self.deadline)
            self.admitted = True
        elif kind == 'input':
            exact(value, ['v', 'nonce', 'seq', 'type', 'data'])
            require(self.admitted and not self.cleanup and type(value['data']) is str)
            data = base64.b64decode(value['data'], validate=True)
            require(base64.b64encode(data).decode() == value['data'] and len(data) <= self.max_control_line and len(self.child_input) + len(data) <= self.max_control_line)
            self.child_input.extend(data)
        elif kind == 'stop':
            exact(value, ['v', 'nonce', 'seq', 'type', 'reason'])
            require(value['reason'] in ['retained', 'deadline', 'cancelled', 'error'])
            self.initiate(value['reason'])
        else:
            raise Invalid()

    def service(self, wait=0):
        now = time.monotonic()
        if self.cleanup:
            require(now < self.cleanup_deadline)
        else:
            if now >= self.deadline:
                self.initiate('deadline', {'kind': 'deadline', 'source': 'supervisor', 'elapsedMs': int((now - START) * 1000)})
            if self.init and self.admitted:
                kills = counters('/sys/fs/cgroup/memory.events')['oom_kill']
                if kills > self.initial_oom_kills:
                    self.initiate('memory', {'kind': 'memory', 'source': 'memory.events', 'before': self.initial_oom_kills, 'after': kills})
        readers = ([] if self.host_eof else [0])
        for descriptor in [self.child_out, self.child_err, self.probe]:
            if descriptor is not None:
                readers.append(descriptor)
        writers = ([1] if self.output else []) + ([self.child_in] if self.child_in is not None and self.child_input and not self.cleanup else [])
        readable, writable, _ = select.select(readers, writers, [], wait)
        if 1 in writable:
            try:
                sent = os.write(1, self.output)
                del self.output[:sent]
            except BlockingIOError:
                pass
            except BrokenPipeError:
                if not self.cleanup:
                    self.host_eof = True
                    raise Invalid()
                self.output.clear()
        if self.child_in in writable:
            try:
                sent = os.write(self.child_in, self.child_input)
                del self.child_input[:sent]
            except BlockingIOError:
                pass
            except BrokenPipeError:
                raise Invalid()
        for descriptor in readable:
            try:
                data = os.read(descriptor, min(16384, self.maximum))
            except BlockingIOError:
                continue
            if descriptor == 0:
                if not data:
                    self.host_eof = True
                    if not self.cleanup:
                        raise Invalid()
                    continue
                self.host_bytes += len(data)
                require(self.host_bytes <= 16 * self.max_control_line + ((self.disk_samples + 1) * 1024 if self.disk_samples else 0))
                require(len(self.input) + len(data) <= self.max_control_line)
                self.input.extend(data)
                while b'\n' in self.input:
                    line, _, tail = self.input.partition(b'\n')
                    self.input = bytearray(tail)
                    if not self.cleanup:
                        self.host_packet(line)
            elif descriptor == self.probe:
                if not self.attachable:
                    require(data == b'A')
                    self.attachable = True
                else:
                    require(data == b'P' and not self.protection)
                    self.protection = True
                    os.close(self.probe)
                    self.probe = None
            elif descriptor == self.child_err:
                self.stderr_bytes += len(data)
                require(self.stderr_bytes <= self.maximum)
                if not data:
                    os.close(self.child_err)
                    self.child_err = None
            elif descriptor == self.child_out:
                self.child_bytes += len(data)
                # At most ten <=maximum payload files plus bounded frame/schema overhead.
                require(self.child_bytes <= self.max_child_bytes)
                if data:
                    if not self.cleanup:
                        self.emit('data', data=base64.b64encode(data).decode())
                else:
                    os.close(self.child_out)
                    self.child_out = None

    def begin_cleanup(self):
        if not self.cleanup:
            self.cleanup = True
            milliseconds = self.init['limits']['cleanupTimeoutMs'] if self.init else 1
            self.cleanup_deadline = time.monotonic() + milliseconds / 1000
            self.child_input.clear()


class Tracer:
    def __init__(self, pump):
        self.pump = pump
        self.tasks, self.retired = {}, set()
        self.root = self.root_exit = None
        self.stores = {}
        self.counts = {key: 0 for key in ['fork', 'vfork', 'clone', 'exec', 'exitEvent', 'signal', 'seccomp', 'interrupt', 'allStop', 'writes', 'execMigrations']}
        self.before_filters = security()
        self.layered_verified = False
        self.last_event = None
        self.progress = {'phase': 'starting', 'tid': None, 'store': None, 'regular': None, 'syscall': None}
        for folder, name in [('/tmp', 'tmp'), ('/work', 'work'), ('/dev/shm', 'shm')]:
            descriptor = os.open(folder, os.O_PATH)
            self.stores[name] = {'fd': descriptor, 'device': os.fstat(descriptor).st_dev, 'mount': self.mount_id(descriptor)}

    def progress_state(self):
        running = None
        for tid, task in sorted(self.tasks.items()):
            if task['stopped']:
                continue
            kernel_state = 'unknown'
            try:
                row = next(line for line in read_small('/proc/%d/status' % tid).splitlines() if line.startswith('State:'))
                value = row.split()[1]
                if value in ['R', 'S', 'D', 'T', 't', 'Z', 'X', 'I']:
                    kernel_state = value
            except BaseException:
                pass
            running = {'tid': tid, 'kernelState': kernel_state, 'lastStop': task['lastStop'], 'new': task['new'],
                       'interrupting': task['interrupting'], 'pendingWrite': task['entry'] is not None}
            break
        return {**self.progress, 'tracked': len(self.tasks), 'stopped': sum(1 for task in self.tasks.values() if task['stopped']),
                'retiringStopped': sum(1 for task in self.tasks.values() if task['stopped'] and task['exiting']), 'running': running, 'lastEvent': self.last_event}

    @staticmethod
    def mount_id(descriptor):
        return int(next(line.split()[1] for line in read_small('/proc/self/fdinfo/' + str(descriptor)).splitlines() if line.startswith('mnt_id:')))

    def add(self, tid, orphan=False):
        # A late creator confirms a live orphan or its already reaped identity.
        if tid in self.tasks:
            require(not orphan and self.tasks[tid]['orphan'])
            self.tasks[tid]['orphan'] = False
            return
        if tid in self.retired:
            require(not orphan)
            self.retired.remove(tid)
            return
        self.tasks[tid] = {'stopped': False, 'new': True, 'interrupting': False, 'signal': 0, 'entry': None,
                           'exiting': False, 'awaitStatus': False, 'vforkChild': None, 'lastStop': 'new', 'orphan': orphan}

    def resume(self, tid, op=None):
        task = self.tasks[tid]
        require(task['stopped'] and not task['awaitStatus'])
        if op is None:
            op = SYSCALL if task['entry'] is not None else CONT
        try:
            ptrace(op, tid, 0, task['signal'])
        except Invalid as error:
            if error.detail['errno'] != errno.ESRCH:
                raise
            # A dying sibling may lose ptrace access before its final wait. Never
            # issue the same request again or use ESRCH as a closure certificate.
            task['awaitStatus'] = True
        task.update(stopped=False, signal=0)

    @staticmethod
    def release_entry(task):
        entry = task['entry']
        if entry is not None and entry.get('held') is not None:
            os.close(entry['held'])
        task['entry'] = None

    def wait(self, until=None):
        while True:
            self.pump.service()
            tid, value = os.waitpid(-1, WAITALL | os.WNOHANG)
            if tid:
                return tid, value
            if until is not None and until():
                return None
            self.pump.service(0.001)

    def ingest(self, tid, value):
        if tid not in self.tasks and os.WIFSTOPPED(value) and value >> 16 == 4:
            # exec may replace an already retired leader identity with an owned
            # nonleader; the actual EXEC/GETEVENTMSG is the migration evidence.
            require(event_message(tid) in self.tasks)
            orphan = tid in self.retired
            self.retired.discard(tid)
            self.add(tid, orphan=orphan)
        if tid not in self.tasks:
            # A newborn's stop or death can precede (or outlive) its creator event.
            # Own it immediately so barriers, writes and closure use the same tasks.
            require(os.WIFEXITED(value) or os.WIFSIGNALED(value) or os.WIFSTOPPED(value)
                    and (value >> 16 == 128 and os.WSTOPSIG(value) in [signal.SIGTRAP, signal.SIGSTOP]
                         or value >> 16 == 6 and os.WSTOPSIG(value) == signal.SIGTRAP))
            self.add(tid, orphan=True)
        task = self.tasks[tid]
        if os.WIFEXITED(value) or os.WIFSIGNALED(value):
            if tid == self.root:
                self.root_exit = {'exitCode': os.WEXITSTATUS(value) if os.WIFEXITED(value) else None,
                                  'signal': os.WTERMSIG(value) if os.WIFSIGNALED(value) else None}
            lost = task['entry'] is not None and task['entry']['phase'] in ['held', 'async']
            self.release_entry(task)
            del self.tasks[tid]
            if task['orphan']:
                self.retired.add(tid)
            require(not lost)
            return
        require(os.WIFSTOPPED(value))
        sig, event = os.WSTOPSIG(value), value >> 16
        # Group exit can supersede an already reported birth/interrupt stop.
        require(not task['stopped'] or event == 6 and sig == signal.SIGTRAP)
        self.last_event = {'tid': tid, 'signal': sig, 'event': event, 'previousStop': task['lastStop'],
                           'new': task['new'], 'interrupting': task['interrupting'],
                           'entryPhase': task['entry']['phase'] if task['entry'] is not None else None}
        # Request/notification correspondence is not one-to-one: any entered
        # trap clears JOBCTL_TRAP_STOP, while a request racing an already-entered
        # trap survives it. Only an actual wait status certifies a stopped task.
        task['stopped'], task['awaitStatus'], task['interrupting'] = True, False, False
        if event in [1, 2, 3]:
            task['lastStop'] = 'fork_event'
            self.counts[{1: 'fork', 2: 'vfork', 3: 'clone'}[event]] += 1
            new = event_message(tid)
            if event == 2:
                task['vforkChild'] = new
            self.add(new)
        elif event == 4:
            self.counts['exec'] += 1
            old = event_message(tid)
            self.release_entry(task)
            if old != tid:
                previous = self.tasks.pop(old, None)
                require(previous is not None)
                self.release_entry(previous)
                if previous['orphan']:
                    self.retired.add(old)
                self.counts['execMigrations'] += 1
            task.update(lastStop='exec_event', exiting=False, new=False,
                        awaitStatus=False, vforkChild=None, signal=0)
        elif event == 5:
            require(task['vforkChild'] is not None)
            task['lastStop'], task['vforkChild'] = 'vfork_done', None
        elif event == 6:
            require(sig == signal.SIGTRAP and not task['exiting'])
            task['lastStop'], task['exiting'] = 'exit_event', True
            self.counts['exitEvent'] += 1
            lost = task['entry'] is not None and task['entry']['phase'] in ['held', 'async']
            self.release_entry(task)
            require(not lost)
        elif event == 7:
            task['lastStop'] = 'syscall_entry'
            self.counts['seccomp'] += 1
            entry = syscall_info(tid)
            require(entry['op'] == 3 and entry['nr'] in [1, 18] and task['entry'] is None)
            task['entry'] = {**entry, 'phase': 'pending', 'held': None, 'identity': None, 'store': None}
            if not self.layered_verified:
                require(security(tid) == self.before_filters + 1)
                self.layered_verified = True
        elif event == 128:
            task['lastStop'] = 'event_stop'
            # EVENT_STOP/SIGTRAP is a kernel stop on this exact seized identity;
            # payload SIGTRAP is event=0 and cannot forge it. Coalesced/racing
            # INTERRUPTs and automatic child stops cannot be counted as tokens.
            # User group stops remain unsupported, including SIGSTOP after birth.
            require(sig == signal.SIGTRAP or task['new'] and sig == signal.SIGSTOP)
            task['new'], task['interrupting'] = False, False
        elif event == 0 and sig == signal.SIGTRAP | 0x80:
            entry = task['entry']
            require(entry is not None and entry['phase'] in ['held', 'async'])
            result = syscall_info(tid)
            require(result['op'] == 2 and result['rval'] not in [-515, -516])
            task['lastStop'] = 'syscall_exit'
            if entry['phase'] == 'held':
                found, identity = os.fstat(entry['held']), entry['identity']
                require((found.st_dev, found.st_ino, self.mount_id(entry['held'])) == (identity['device'], identity['inode'], identity['mountId']))
            if result['rval'] in [-512, -513, -514]:
                # ptrace(2): INTERRUPT may report a restarting syscall exit.
                # No bytes were written; signal delivery and a fresh seccomp
                # entry must see no old FD identity or pending exit.
                self.release_entry(task)
                return
            self.counts['writes'] += 1
            self.progress['phase'] = 'syscall_exit_observed'
            if result['isError'] and result['rval'] == -errno.ENOSPC:
                # An asynchronously reclassified FD cannot prove disk identity.
                require(entry['phase'] == 'held')
                self.pump.initiate('disk', {'kind': 'disk', 'tid': tid, 'syscall': 'write' if entry['nr'] == 1 else 'pwrite64',
                    'errno': 28, 'returned': -28, 'store': entry['store'], **entry['identity'], 'stopBeforeNextInstruction': True})
            self.release_entry(task)
        else:
            task['lastStop'] = 'signal_stop'
            require(event == 0 and sig not in [signal.SIGTRAP, signal.SIGSTOP, signal.SIGTRAP | 0x80])
            self.counts['signal'] += 1
            require(task['entry'] is None)
            task['signal'] = sig
        # EXIT cannot return to userspace. VFORK cannot return before the enabled
        # VFORK_DONE stop. Drain both kernel-only paths even during a live barrier.
        if task['exiting'] or task['vforkChild'] is not None:
            self.resume(tid, CONT)

    def all_stop(self):
        self.progress = {'phase': 'all_stopping', 'tid': None, 'store': None, 'regular': None, 'syscall': None}
        def interrupt_running():
            for tid, task in list(self.tasks.items()):
                if not task['stopped'] and not task['new'] and not task['interrupting'] and not task['awaitStatus'] and not task['exiting'] and task['vforkChild'] is None:
                    try:
                        ptrace(INTERRUPT, tid)
                        task['interrupting'] = True
                        self.counts['interrupt'] += 1
                    except Invalid as error:
                        if error.detail['errno'] != errno.ESRCH:
                            raise
                        task['awaitStatus'] = True
        interrupt_running()
        while not all(task['stopped'] or task['exiting'] or task['vforkChild'] is not None for task in self.tasks.values()):
            self.ingest(*self.wait())
            interrupt_running()
        self.counts['allStop'] += 1

    def observe(self, tid):
        require(all(task['stopped'] or task['exiting'] or task['vforkChild'] is not None for task in self.tasks.values()))
        task, held = self.tasks[tid], None
        entry = task['entry']
        require(entry is not None and entry['phase'] == 'pending' and task['stopped'])
        # The x86-64 ABI interprets FD arguments as signed int, not raw u64.
        descriptor = C.c_int(entry['args'][0] & 0xffffffff).value
        try:
            held = os.open('/proc/%d/fd/%d' % (tid, descriptor), os.O_PATH)
        except OSError as error:
            require(error.errno == errno.ENOENT)
        identity, store = None, None
        if held is not None:
            found, mount = os.fstat(held), self.mount_id(held)
            if stat.S_ISREG(found.st_mode):
                for name, expected in self.stores.items():
                    if found.st_dev == expected['device'] and mount == expected['mount']:
                        store = name
                        identity = {'device': integer(found.st_dev), 'inode': integer(found.st_ino), 'mountId': integer(mount, True)}
                        break
        self.progress = {'phase': 'awaiting_write_exit', 'tid': tid, 'store': store,
                         'regular': stat.S_ISREG(found.st_mode) if held is not None else None,
                         'syscall': 'write' if entry['nr'] == 1 else 'pwrite64'}
        if store is None:
            if held is not None:
                os.close(held)
            entry['phase'] = 'async'
            return
        entry.update(phase='held', held=held, identity=identity, store=store)
        self.resume(tid, SYSCALL)
        while tid in self.tasks and self.tasks[tid]['entry'] is entry:
            self.ingest(*self.wait())
            if tid in self.tasks and self.tasks[tid]['entry'] is entry and self.tasks[tid]['stopped']:
                # Only an already requested interrupt may intervene before EXIT.
                require(self.tasks[tid]['lastStop'] == 'event_stop')
                self.resume(tid, SYSCALL)
        require(tid in self.tasks and self.tasks[tid]['lastStop'] == 'syscall_exit')

    def step(self, until=None):
        self.progress = {'phase': 'waiting_event', 'tid': None, 'store': None, 'regular': None, 'syscall': None}
        status = self.wait(until)
        if status is None:
            return
        self.ingest(*status)
        if any(task['entry'] is not None and task['entry']['phase'] == 'pending' for task in self.tasks.values()):
            self.all_stop()
            while self.tasks and any(task['entry'] is not None and task['entry']['phase'] == 'pending' for task in self.tasks.values()):
                self.observe(next(tid for tid, task in self.tasks.items() if task['entry'] is not None and task['entry']['phase'] == 'pending'))
        for tid, task in list(self.tasks.items()):
            if task['stopped']:
                self.resume(tid)

    def launch(self):
        gate_read, gate_write = os.pipe()
        ready_read, ready_write = os.pipe()
        input_read, input_write = os.pipe()
        output_read, output_write = os.pipe()
        error_read, error_write = os.pipe()
        self.root = os.fork()
        if self.root == 0:
            try:
                # Parent is permanently non-dumpable; only the tracee is made attachable.
                require(LIB.prctl(4, 1, 0, 0, 0) == 0)
                for descriptor in [gate_write, ready_read, input_write, output_read, error_read]:
                    os.close(descriptor)
                # fork inherits dumpable=0. The parent must not race SEIZE against
                # the child setting dumpable=1; this trusted child waits at gate A.
                require(os.write(ready_write, b'A') == 1)
                require(os.read(gate_read, 1) == b'A')
                restrict_child()
                for file, flags in [('/proc/1/fd', os.O_RDONLY | os.O_DIRECTORY), ('/proc/1/fd/0', os.O_RDONLY | os.O_NONBLOCK),
                                    ('/proc/1/fd/1', os.O_WRONLY | os.O_NONBLOCK), ('/proc/1/mem', os.O_RDONLY)]:
                    try:
                        descriptor = os.open(file, flags)
                    except OSError as error:
                        require(error.errno in [errno.EACCES, errno.EPERM])
                    else:
                        os.close(descriptor)
                        raise Invalid()
                require(os.write(ready_write, b'P') == 1)
                os.close(ready_write)
                require(os.read(gate_read, 1) == b'B')
                os.close(gate_read)
                os.dup2(input_read, 0); os.dup2(output_write, 1); os.dup2(error_write, 2)
                os.closerange(3, int(os.sysconf('SC_OPEN_MAX')))
                environment = {'HOME': '/work', 'TMPDIR': '/tmp', 'TMP': '/tmp', 'TEMP': '/tmp', 'USERPROFILE': '/work',
                    'XDG_CONFIG_HOME': '/work', 'XDG_CACHE_HOME': '/work', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'NO_COLOR': '1',
                    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/work/empty-gitconfig', 'GIT_NO_LAZY_FETCH': '1',
                    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0', 'GIT_ATTR_NOSYSTEM': '1'}
                os.chdir('/work')
                os.execve('/usr/local/bin/node', ['/usr/local/bin/node', '/app/internal/linux-job-controller.mjs'], environment)
            except BaseException:
                os._exit(4)
        for descriptor in [gate_read, ready_write, input_read, output_write, error_write]:
            os.close(descriptor)
        self.pump.child_in, self.pump.child_out, self.pump.child_err, self.pump.probe = input_write, output_read, error_read, ready_read
        for descriptor in [input_write, output_read, error_read, ready_read]:
            os.set_blocking(descriptor, False)
        while not self.pump.attachable:
            self.pump.service(0.001)
        self.add(self.root)
        ptrace(SEIZE, self.root, 0, OPTIONS)
        ptrace(INTERRUPT, self.root)
        self.tasks[self.root]['interrupting'] = True
        self.ingest(*self.wait())
        require(self.tasks[self.root]['stopped'])
        require(os.write(gate_write, b'A') == 1)
        self.resume(self.root)
        while not self.pump.protection:
            self.step(lambda: self.pump.protection)
            require(bool(self.tasks))
        require(self.layered_verified)
        self.pump.initial_oom_kills = counters('/sys/fs/cgroup/memory.events')['oom_kill']
        require(self.pump.initial_oom_kills == 0)
        startup = boundary(self.pump.init, True)
        self.pump.ready_sample = time.monotonic()
        self.pump.emit('ready', sampleNs=str(time.monotonic_ns()), boundary=startup)
        self.progress['phase'] = 'waiting_admission'
        while not self.pump.admitted:
            self.pump.service(0.001)
        self.progress['phase'] = 'verifying_source'
        verify_source_types(self.pump)
        initial = {'schema': 'scanmux.job-controller-init/v1', 'nonce': self.pump.nonce,
                   'expected': self.pump.init['expected'], 'limits': self.pump.init['limits']}
        if 'operation' in self.pump.init:
            initial['schema'] = 'scanmux.reproduction-controller-init/v1'
            initial['operation'] = self.pump.init['operation']
        if 'copyBudgetBytes' in self.pump.init:
            initial['copyBudgetBytes'] = self.pump.init['copyBudgetBytes']
        if 'maxJobDiskBytes' in self.pump.init:
            initial['maxJobDiskBytes'] = self.pump.init['maxJobDiskBytes']
        encoded = json.dumps(initial, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'
        require(len(encoded) <= 65536 and len(self.pump.child_input) == 0)
        self.pump.child_input.extend(encoded)
        require(os.write(gate_write, b'B') == 1)
        os.close(gate_write)
        while self.tasks:
            self.step()
        require(self.root_exit is not None)
        return startup

    def kill_reap(self):
        self.pump.begin_cleanup()
        # PID 1's verified private namespace contains only this owner's descendants.
        for name in os.listdir('/proc'):
            if name.isdecimal() and int(name) != 1:
                try:
                    os.kill(int(name), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        while True:
            try:
                tid, value = self.wait()
            except ChildProcessError:
                break
            if os.WIFSTOPPED(value):
                try:
                    ptrace(CONT, tid, 0, signal.SIGKILL)
                except Invalid:
                    # A terminal wait is still required; ESRCH alone does not release ownership.
                    pass
            elif os.WIFEXITED(value) or os.WIFSIGNALED(value):
                if tid == self.root:
                    self.root_exit = {'exitCode': os.WEXITSTATUS(value) if os.WIFEXITED(value) else None,
                                      'signal': os.WTERMSIG(value) if os.WIFSIGNALED(value) else None}
                task = self.tasks.pop(tid, None)
                if task is not None:
                    self.release_entry(task)
            else:
                raise Invalid()
        require(not self.tasks and [name for name in os.listdir('/proc') if name.isdecimal()] == ['1'])

    def close(self):
        for store in self.stores.values():
            os.close(store['fd'])


def main():
    require(len(sys.argv) == 4)
    nonce, wall, maximum = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    require(len(nonce) == 36 and all(character in '0123456789abcdef-' for character in nonce))
    integer(wall, True); integer(maximum, True)
    require(wall <= 2147483647 and maximum <= 2147483647 and os.getpid() == 1)
    os.umask(0o077)
    require(LIB.prctl(4, 0, 0, 0, 0) == 0 and LIB.prctl(3, 0, 0, 0, 0) == 0)
    pump, tracer = Pump(nonce, wall, maximum), None
    completed, interruption = False, None
    try:
        while not pump.initialized:
            pump.service(0.001)
        limits = pump.init['limits']
        require(limits['wallMs'] == wall and limits['retainedBytes'] >= 2 * maximum)
        chunks = 10 * ((maximum + min(16384, maximum) - 1) // min(16384, maximum)) + 12 + 7
        pump.max_child_bytes = chunks * (1024 + 4 * ((min(16384, maximum) + 2) // 3))
        if pump.disk_samples:
            pump.max_child_bytes += pump.disk_samples * 1024
        boundary(pump.init, False)
        verify_assets(pump.init)
        with open('/work/empty-gitconfig', 'x', encoding='utf-8') as git_config:
            # Trust only the operator-selected readonly mapping, never all repositories.
            require(pump.init['expected']['mappedRoot'].startswith('/repo/') and len(pump.init['expected']['mappedRoot']) == 70)
            git_config.write('[safe]\n\tdirectory = ' + pump.init['expected']['mappedRoot'] + '\n')
        tracer = Tracer(pump)
        tracer.launch()
        completed = True
    except Stopping:
        interruption = tracer.progress_state() if tracer else None
    except BaseException as error:
        interruption = tracer.progress_state() if tracer else None
        try:
            detail = error.detail if isinstance(error, Invalid) else {'kind': 'os' if isinstance(error, OSError) else 'unexpected', 'operation': 'unknown', 'site': 1,
                'errno': error.errno if isinstance(error, OSError) and type(error.errno) is int and error.errno >= 0 else None}
            if not isinstance(error, Invalid):
                trace = error.__traceback__
                while trace:
                    if trace.tb_frame.f_code.co_filename == __file__:
                        detail['operation'] = trace.tb_frame.f_code.co_name if trace.tb_frame.f_code.co_name in OPERATIONS else 'unknown'
                        detail['site'] = trace.tb_lineno
                    trace = trace.tb_next
            if detail['operation'] in ['add', 'resume', 'wait', 'ingest', 'all_stop', 'observe', 'step', 'launch', 'ptrace', 'syscall_info', 'event_message']:
                code = 'job_native_observer_failed'
            elif not pump.admitted or detail['operation'] in ['boundary', 'verify_assets', 'verify_source_types', 'security', 'safe_root_probe', 'mount_info']:
                code = 'job_boundary_unverified'
            else:
                code = 'job_protocol_invalid'
            pump.emit('failure', code=code, detail=detail)
        except BaseException:
            pass
    finally:
        try:
            pump.begin_cleanup()
            if tracer is not None:
                tracer.kill_reap()
            else:
                require([name for name in os.listdir('/proc') if name.isdecimal()] == ['1'])
            # Drain bounded pipe tails; after an owned stop they are discarded, never results.
            while pump.child_out is not None or pump.child_err is not None:
                pump.service(0.001)
            ending = boundary(pump.init, pump.protection) if pump.init and pump.protection else None
            if tracer is not None:
                tracer.close()
            pump.emit('closed', boundary=ending, rootTerminal=tracer.root_exit if tracer else None,
                      allOwnedTasksReaped=True, counts=tracer.counts if tracer else None,
                      stopReason=pump.stop_reason, controllerCompleted=completed, interruption=interruption)
            while pump.output:
                pump.service(0.001)
            return 0 if completed or pump.stop_reason else 4
        except BaseException:
            return 4


if __name__ == '__main__':
    try:
        result = main()
    except BaseException:
        result = 4
    os._exit(result)
