import ast
import ctypes as C
import errno
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

for stream in [sys.stdin, sys.stdout, sys.stderr]:
    stream.reconfigure(encoding='utf-8')

source = Path(__file__).resolve().parents[2] / 'internal/linux-job-supervisor.py'
tree = ast.parse(source.read_text(encoding='utf-8'))
names = {'Invalid', 'Stopping', 'Pump', 'Tracer', 'require', 'integer'}
constants = {'SEIZE', 'WAITALL', 'MAX_INTEGER', 'OPERATIONS'}
nodes = [node for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in names
         or isinstance(node, ast.Assign) and any(isinstance(item, ast.Name) and item.id in constants
                                                for target in node.targets for item in ast.walk(target))]
code = compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec')
SIGTRAP, SIGSTOP, SIGKILL = 5, 19, 9


def stop(event=128, sig=SIGTRAP):
    return event << 16 | sig << 8 | 0x7f


class Kernel:
    def __init__(self):
        self.live, self.dead, self.events, self.calls, self.closed = set(), set(), [], [], []
        self.messages, self.info, self.proc_status = {}, {}, {}
        self.packets = []
        self.fd_mode = stat.S_IFREG
        self.os = SimpleNamespace(O_PATH=0x200000, WNOHANG=1, open=self.open, close=self.closed.append,
            fstat=lambda fd: SimpleNamespace(st_dev=1, st_ino=fd, st_mode=self.fd_mode),
            WIFSTOPPED=lambda value: value & 0xff == 0x7f, WSTOPSIG=lambda value: value >> 8 & 0xff,
            WIFEXITED=lambda value: value & 0x7f == 0, WEXITSTATUS=lambda value: value >> 8 & 0xff,
            WIFSIGNALED=lambda value: 0 < value & 0x7f < 0x7f, WTERMSIG=lambda value: value & 0x7f,
            waitpid=self.waitpid, listdir=lambda folder: ['1'] + [str(tid) for tid in sorted(self.live)],
            kill=lambda tid, sig: self.calls.append(('kill', tid, sig)))
        self.namespace = {'os': self.os, 'C': C, 'errno': errno, 'stat': stat, 'sys': sys,
            'signal': SimpleNamespace(SIGTRAP=SIGTRAP, SIGSTOP=SIGSTOP, SIGKILL=SIGKILL),
            'security': lambda tid='self': 1, 'read_small': self.read_small,
            'ptrace': self.ptrace, 'event_message': lambda tid: self.messages[tid],
            'syscall_info': lambda tid: self.info[tid].pop(0)}
        exec(code, self.namespace)
        self.pump = SimpleNamespace(service=lambda delay=0: None, begin_cleanup=lambda: None, initiate=self.initiate,
            stop_reason=None, stop_event=None, emit=lambda kind, **fields: self.packets.append((kind, fields)))
        self.tracer = self.namespace['Tracer'](self.pump)
        self.tracer.root = 100
        self.tracer.layered_verified = True
        self.live.add(100)
        self.tracer.add(100)

    def open(self, file, flags):
        if file in ['/tmp', '/work', '/dev/shm']:
            return {'/tmp': 10, '/work': 11, '/dev/shm': 12}[file]
        assert file.startswith('/proc/') and '/fd/' in file, file
        assert all(task['stopped'] or task['exiting'] or task['vforkChild'] is not None
                   for task in self.tracer.tasks.values()), 'FD identity sampled without an all-stop'
        return 50

    def read_small(self, file):
        if file.endswith('/status'):
            tid = int(file.split('/')[2])
            if tid not in self.live | self.proc_status.keys():
                raise FileNotFoundError(errno.ENOENT, 'no such task', file)
            state, tracer = self.proc_status.get(tid, ('S', 1))
            return 'State:\t%s\nTracerPid:\t%d' % (state, tracer)
        assert file.startswith('/proc/self/fdinfo/'), file
        return 'mnt_id: 1'

    def ptrace(self, op, tid, address=0, data=0):
        self.calls.append((op, tid, data))
        if getattr(self, 'esrch', None) == (op, tid):
            raise self.namespace['Invalid'](errno.ESRCH)
        return 0

    def initiate(self, reason, event=None):
        try:
            self.namespace['Pump'].initiate(self.pump, reason, event)
        finally:
            self.stopped = self.pump.stop_reason, self.pump.stop_event

    def waitpid(self, tid, flags):
        assert tid == -1 and flags == self.namespace['WAITALL'] | self.os.WNOHANG
        if not self.events:
            if not self.live:
                raise ChildProcessError()
            raise AssertionError('no waitable status: a stopped task cannot make progress')
        event = self.events.pop(0)
        if callable(event):
            event = event()
        self.account(*event)
        return event

    def account(self, tid, value):
        if self.os.WIFEXITED(value) or self.os.WIFSIGNALED(value):
            self.live.discard(tid)
            self.dead.add(tid)
        else:
            if value >> 16 == 4 and self.messages.get(tid, tid) != tid:
                self.live.discard(self.messages[tid])
            self.live.add(tid)

    def ingest(self, tid, value):
        self.account(tid, value)
        self.tracer.ingest(tid, value)

    def creator(self, event, child=101):
        if child not in self.dead:
            self.live.add(child)
        self.messages[100] = child
        self.ingest(100, stop(event))
        if self.tracer.tasks[100]['stopped']:
            self.tracer.resume(100)

    def reap(self):
        pending = set(self.tracer.tasks)
        self.events = [(tid, stop(6)) for tid in sorted(self.live)]
        for tid in sorted(self.live):
            def terminal(tid=tid):
                assert set(self.tracer.tasks) == pending, 'ownership released before terminal wait'
                pending.discard(tid)
                return tid, SIGKILL
            self.events.append(terminal)
        self.tracer.kill_reap()
        assert not self.tracer.tasks and not self.live and not self.events
        self.tracer.close()
        assert all(fd in self.closed for fd in [10, 11, 12])


def lifecycle(sequence, arrival):
    cases = 0
    for event in [1, 2, 3]:
        for terminal in [0, SIGKILL]:
            for sig in ([SIGTRAP, SIGSTOP] if sequence == 'birth-exit' else [SIGTRAP]):
                kernel = Kernel()
                tracer = kernel.tracer
                if arrival == 'before':
                    kernel.creator(event)
                if sequence == 'birth-exit':
                    kernel.ingest(101, stop(sig=sig))
                    assert 101 in tracer.tasks and tracer.tasks[101]['stopped']
                    assert not any(call[:2] == (7, 101) for call in kernel.calls)
                    if arrival == 'after-birth':
                        task = tracer.tasks[101]
                        kernel.creator(event)
                        assert tracer.tasks[101] is task, 'creator reset an owned task'
                if sequence != 'terminal-first':
                    kernel.ingest(101, stop(6))
                    assert 101 in tracer.tasks and tracer.tasks[101]['exiting']
                    assert not tracer.tasks[101]['stopped'] and (7, 101, 0) in kernel.calls
                    if arrival == 'after-exit':
                        kernel.creator(event)
                kernel.ingest(101, terminal)
                assert 101 not in tracer.tasks
                if arrival == 'after-terminal':
                    kernel.creator(event)
                    assert 101 not in tracer.tasks, 'late creator resurrected a reaped task'
                kernel.reap()
                cases += 1
    return cases


def progress(scenario):
    kernel = Kernel()
    tracer = kernel.tracer
    kernel.ingest(100, stop())
    if scenario in ['birth-barrier', 'creator-during-write']:
        kernel.ingest(101, stop())
        tracer.all_stop()
        assert tracer.counts['allStop'] == 1 and 101 in tracer.tasks
        tracer.resume(100)
        kernel.events = [(101, stop(7)), (100, stop(3) if scenario == 'creator-during-write' else stop())]
        kernel.messages[100] = 101
        kernel.info[101] = [{'op': 3, 'nr': 1, 'args': [4, 0, 1, 0, 0, 0]},
                            {'op': 2, 'rval': -errno.ENOSPC, 'isError': True}]
        tracer.resume(101)
        kernel.events.append((101, stop(0, SIGTRAP | 0x80)))
        try:
            tracer.step()
        except kernel.namespace['Stopping']:
            pass
        else:
            raise AssertionError('orphan write escaped disk accounting')
        reason, observed = kernel.stopped
        assert reason == 'disk' and observed['store'] == 'tmp' and observed['stopBeforeNextInstruction']
        assert observed['returned'] == -28 and observed['tid'] == 101 and tracer.counts['writes'] == 1
        assert sum(call[:2] == (7, 101) for call in kernel.calls) == 1, 'writer resumed after ENOSPC'
        kernel.reap()
        assert 50 in kernel.closed
    elif scenario == 'closure-needs-terminal':
        kernel.ingest(101, stop())
        kernel.events = [(100, SIGKILL), (101, stop(6))]
        try:
            tracer.kill_reap()
        except AssertionError as error:
            assert str(error) == 'no waitable status: a stopped task cannot make progress'
        else:
            raise AssertionError('cleanup certified closure without a terminal wait')
        assert 101 in tracer.tasks and 101 in kernel.live
        kernel.reap()
    elif scenario == 'birth-during-observe':
        tracer.resume(100)
        kernel.info[100] = [{'op': 3, 'nr': 1, 'args': [4, 0, 1, 0, 0, 0]},
                            {'op': 2, 'rval': 1, 'isError': False}]
        kernel.events = [(100, stop(7)), (101, stop()), (100, stop(0, SIGTRAP | 0x80))]
        tracer.step()
        assert not kernel.events and tracer.counts['writes'] == 1
        assert 101 in tracer.tasks and not tracer.tasks[101]['stopped']
        assert (7, 101, 0) in kernel.calls, 'child left stopped after observe returned'
        kernel.events = [(100, stop()), (101, stop())]
        tracer.all_stop()
        assert not kernel.events and all(task['stopped'] for task in tracer.tasks.values())
        kernel.reap()
    elif scenario == 'exit-esrch':
        kernel.ingest(101, stop())
        kernel.esrch = 7, 101
        kernel.ingest(101, stop(6))
        assert 101 in tracer.tasks and tracer.tasks[101]['awaitStatus']
        kernel.events = [(101, SIGKILL)]
        tracer.step()
        assert 101 not in tracer.tasks
        kernel.reap()
    elif scenario == 'observed-order':
        tracer.resume(100)
        tracer.tasks[100]['entry'] = {'phase': 'async', 'held': None}
        kernel.info[100] = [{'op': 2, 'rval': 1, 'isError': False}]
        kernel.ingest(101, 0x80057f)
        kernel.ingest(100, 0x857f)
        tracer.resume(100)
        assert kernel.calls[-1] == (7, 100, 0)
        kernel.ingest(101, 0x6057f)
        assert 101 in tracer.tasks and kernel.calls[-1] == (7, 101, 0)
        kernel.ingest(101, 0)
        kernel.reap()
    else:
        raise AssertionError(scenario)
    return 1


def anomalies():
    cases = 0
    for value in [stop(0), stop(0, SIGSTOP), stop(0, 10), stop(0, SIGTRAP | 0x80),
                  stop(7), stop(1), stop(5), stop(128, 10), stop(6, SIGSTOP), 0xffff]:
        kernel = Kernel()
        try:
            kernel.ingest(101, value)
        except kernel.namespace['Invalid'] as error:
            assert error.detail['operation'] == 'ingest'
        else:
            raise AssertionError('accepted unrelated unknown stop: %x' % value)
        kernel.reap()
        cases += 1
    for kind in ['duplicate-stop', 'unmatched-exec', 'duplicate-exit', 'payload-sigtrap',
                 'payload-group-stop', 'syscall-without-entry']:
        kernel = Kernel()
        tracer = kernel.tracer
        if kind == 'duplicate-stop':
            kernel.ingest(101, stop())
            action = lambda: kernel.ingest(101, stop())
        elif kind == 'unmatched-exec':
            kernel.messages[101] = 999
            action = lambda: kernel.ingest(101, stop(4))
        elif kind == 'duplicate-exit':
            kernel.ingest(101, stop(6))
            action = lambda: kernel.ingest(101, stop(6))
        else:
            kernel.ingest(101, stop())
            tracer.resume(101)
            sig = {'payload-sigtrap': SIGTRAP, 'payload-group-stop': SIGSTOP,
                   'syscall-without-entry': SIGTRAP | 0x80}[kind]
            action = lambda: kernel.ingest(101, stop(0, sig))
        try:
            action()
        except kernel.namespace['Invalid'] as error:
            assert error.detail['operation'] in ['add', 'ingest']
        else:
            raise AssertionError('accepted anomaly: ' + kind)
        kernel.reap()
        cases += 1
    return cases


def exec_migration():
    for claimed in [False, True]:
        kernel = Kernel()
        tracer = kernel.tracer
        if claimed:
            kernel.creator(3, 102)
        kernel.ingest(102, stop())
        tracer.resume(102)
        kernel.ingest(101, stop())
        tracer.resume(101)
        kernel.ingest(102, 0)
        kernel.messages[102] = 101
        kernel.ingest(102, stop(4))
        assert 101 not in tracer.tasks and 102 in tracer.tasks and tracer.counts['execMigrations'] == 1
        if not claimed:
            task = tracer.tasks[102]
            kernel.creator(3, 102)
            assert tracer.tasks[102] is task
        tracer.resume(102)
        kernel.messages[102] = 101
        kernel.ingest(102, stop(3))
        assert 101 not in tracer.tasks, 'late creator resurrected a migrated identity'
        kernel.reap()
    kernel = Kernel()
    kernel.ingest(101, stop())
    kernel.tracer.resume(101)
    kernel.messages[101] = 101
    kernel.ingest(101, stop(4))
    kernel.creator(3)
    assert kernel.tracer.tasks[101]['lastStop'] == 'exec_event'
    kernel.reap()
    return 3


def tid_reuse(scenario, arrival):
    cases = 0
    for event in [1, 2, 3]:
        kernel = Kernel()
        tracer = kernel.tracer
        kernel.ingest(100, stop())
        tracer.resume(100)
        kernel.creator(3, 102)
        kernel.ingest(102, stop())
        tracer.resume(102)
        kernel.ingest(101, stop())
        tracer.resume(101)
        if scenario == 'exec-reuse':
            kernel.ingest(102, 0)
            kernel.messages[102] = 101
            kernel.ingest(102, stop(4))
            tracer.resume(102)
        else:
            kernel.ingest(101, stop(6))
            kernel.ingest(101, 0)
        assert 101 not in tracer.tasks
        if scenario == 'closure-reuse':
            kernel.ingest(102, stop(6))
            kernel.ingest(102, SIGKILL)
        kernel.dead.discard(101)
        if scenario in ['creator-reuse', 'closure-reuse'] or arrival == 'before':
            kernel.creator(event)
            assert 101 in tracer.tasks, 'creator dropped a reused live TID'
            if event == 2:
                kernel.ingest(100, stop(5))
                tracer.resume(100)
        if scenario == 'closure-reuse':
            kernel.events = [(100, stop(6)), (100, 0), (101, stop()), (101, stop(6)), (101, 0)]
            while tracer.tasks:
                tracer.step()
            assert not kernel.live and not kernel.events, 'launch closed with a live child'
        else:
            kernel.ingest(101, stop())
            task = tracer.tasks[101]
            assert task['stopped'], 'birth dropped a reused TID'
            if arrival == 'after-birth':
                kernel.creator(event)
                assert tracer.tasks[101] is task
                if event == 2:
                    kernel.ingest(100, stop(5))
                    tracer.resume(100)
            tracer.resume(101)
            # A still later creator from the old lifetime must not reset this one.
            kernel.messages[102 if 102 in tracer.tasks else 100] = 101
            creator = 102 if 102 in tracer.tasks else 100
            kernel.ingest(creator, stop(3))
            assert tracer.tasks[101] is task and not task['stopped']
            tracer.resume(creator)
            kernel.ingest(101, stop(6))
            assert 101 in tracer.tasks
            kernel.ingest(101, 0)
            if arrival == 'after-terminal':
                kernel.creator(event)
                assert 101 not in tracer.tasks
                if event == 2:
                    kernel.ingest(100, stop(5))
                    tracer.resume(100)
        kernel.reap()
        cases += 1
    return cases


def unreported_child():
    kernel = Kernel()
    kernel.ingest(100, 0)
    kernel.live.add(101)
    assert not kernel.tracer.tasks
    kernel.reap()
    assert ('kill', 101, SIGKILL) in kernel.calls
    kernel = Kernel()
    kernel.ingest(100, 0)
    kernel.live.add(101)
    def no_children():
        raise ChildProcessError()
    kernel.events = [no_children]
    try:
        kernel.tracer.kill_reap()
    except kernel.namespace['Invalid'] as error:
        assert error.detail['operation'] == 'kill_reap'
    else:
        raise AssertionError('final /proc check accepted a live unreported child')
    kernel.reap()
    return 2


def creator_liveness():
    cases = 0
    for event in [1, 2, 3]:
        for state in ['absent', 'traced', 'zombie', 'dead', 'untraced-live']:
            kernel = Kernel()
            if state in ['absent', 'zombie', 'dead']:
                kernel.dead.add(101)
            if state != 'absent':
                kernel.proc_status[101] = {'traced': ('t', 1), 'zombie': ('Z', 0),
                                          'dead': ('X', 0), 'untraced-live': ('S', 0)}[state]
            try:
                kernel.creator(event)
            except kernel.namespace['Invalid'] as error:
                assert state == 'untraced-live' and error.detail['operation'] == 'ingest'
            else:
                assert state != 'untraced-live', 'creator silently accepted an untraced live child'
                assert (101 in kernel.tracer.tasks) == (state == 'traced'), 'creator resurrected an untraced zombie'
            kernel.proc_status.clear()
            kernel.reap()
            cases += 1
    return cases


def write_death(scenario, arrival, phases):
    cases = 0
    for phase in phases:
        for nr in [1, 18]:
            for terminal in [0, SIGKILL]:
                kernel = Kernel()
                tracer = kernel.tracer
                kernel.ingest(100, stop())
                tracer.resume(100)
                if arrival == 'before':
                    kernel.creator(3)
                kernel.ingest(101, stop())
                tracer.resume(101)
                kernel.fd_mode = stat.S_IFREG if phase == 'held' else stat.S_IFIFO
                kernel.info[101] = [{'op': 3, 'nr': nr, 'args': [4, 0, 1, 0, 0, 0]}]
                kernel.events = [(101, stop(7)), (100, stop())]
                death = stop(6) if scenario == 'write-exit' else terminal
                if phase == 'held':
                    kernel.events.append((101, death))
                else:
                    tracer.step()
                    assert tracer.tasks[101]['entry']['phase'] == 'async'
                    kernel.events = [(101, death)]
                try:
                    tracer.step()
                except kernel.namespace['Stopping']:
                    assert phase == 'held', 'async write death stopped the job'
                    assert kernel.stopped == ('error', None), 'death fabricated an ENOSPC observation'
                else:
                    assert phase == 'async', 'lost held write result silently accepted'
                    assert not hasattr(kernel, 'stopped') and kernel.pump.stop_reason is None
                assert not kernel.packets, 'death emitted a fabricated native fact'
                assert tracer.counts['writes'] == 0 and not kernel.info[101]
                assert tracer.progress['phase'] != 'syscall_exit_observed'
                assert kernel.closed.count(50) == 1, 'held FD was leaked or closed twice'
                if scenario == 'write-exit':
                    assert 101 in tracer.tasks and tracer.tasks[101]['entry'] is None
                    assert tracer.tasks[101]['exiting']
                    if arrival == 'after-exit':
                        if tracer.tasks[100]['stopped']:
                            tracer.resume(100)
                        kernel.creator(3)
                    kernel.ingest(101, terminal)
                assert 101 not in tracer.tasks
                if arrival == 'after-terminal':
                    if tracer.tasks[100]['stopped']:
                        tracer.resume(100)
                    kernel.creator(3)
                    assert 101 not in tracer.tasks
                if phase == 'async':
                    kernel.events = [(100, stop(6)), (100, 0)]
                    while tracer.tasks:
                        tracer.step()
                    assert tracer.root_exit == {'exitCode': 0, 'signal': None}
                    assert not kernel.live and not kernel.events and not kernel.packets
                    assert kernel.pump.stop_reason is None and kernel.pump.stop_event is None
                    assert tracer.counts['writes'] == 0
                kernel.reap()
                assert kernel.closed.count(50) == 1
                cases += 1
    return cases


def write_controls():
    cases = 0
    for phase in ['held', 'async']:
        for event in [1, 2, 3, 4, 5, 7, 0]:
            kernel = Kernel()
            tracer = kernel.tracer
            kernel.ingest(100, stop())
            tracer.resume(100)
            entry = {'phase': phase, 'held': 50 if phase == 'held' else None}
            tracer.tasks[100]['entry'] = entry
            kernel.messages[100] = 100 if event == 4 else 101
            tracer.tasks[100]['vforkChild'] = 101 if event == 5 else None
            kernel.info[100] = [{'op': 3, 'nr': 1}]
            try:
                kernel.ingest(100, stop(event, 10 if event == 0 else SIGTRAP))
            except kernel.namespace['Invalid'] as error:
                assert error.detail['operation'] == 'ingest'
            else:
                raise AssertionError('accepted a continuing task with a lost write: %s/%d' % (phase, event))
            assert tracer.tasks[100]['entry'] is entry
            kernel.reap()
            cases += 1
    for death in [stop(6), 0, SIGKILL]:
        kernel = Kernel()
        kernel.ingest(101, stop())
        kernel.tracer.resume(101)
        kernel.info[101] = [{'op': 3, 'nr': 1, 'args': [4, 0, 1, 0, 0, 0]}]
        kernel.ingest(101, stop(7))
        kernel.ingest(101, death)
        assert kernel.tracer.counts['writes'] == 0 and not hasattr(kernel, 'stopped')
        assert 50 not in kernel.closed
        kernel.reap()
        cases += 1
    for reason in ['disk', 'memory', 'deadline', 'retained', 'cancelled', 'error']:
        kernel = Kernel()
        kernel.ingest(101, stop())
        kernel.tracer.resume(101)
        kernel.tracer.tasks[101]['entry'] = {'phase': 'held', 'held': 50}
        kernel.pump.stop_reason, kernel.pump.stop_event = reason, {'prior': True}
        try:
            kernel.ingest(101, stop(6))
        except kernel.namespace['Stopping']:
            assert kernel.stopped == (reason, {'prior': True})
        else:
            raise AssertionError('lost write result did not stop')
        assert not kernel.packets
        kernel.reap()
        cases += 1
    for phase in ['held', 'async']:
        for nr in [1, 18]:
            for result in [1, -errno.EBADF, -errno.ENOSPC, -512]:
                kernel = Kernel()
                tracer = kernel.tracer
                kernel.ingest(100, stop())
                tracer.resume(100)
                kernel.fd_mode = stat.S_IFREG if phase == 'held' else stat.S_IFIFO
                kernel.info[100] = [{'op': 3, 'nr': nr, 'args': [4, 0, 1, 0, 0, 0]},
                                    {'op': 2, 'rval': result, 'isError': result < 0}]
                kernel.events = [(100, stop(7))]
                if phase == 'async':
                    tracer.step()
                kernel.events.append((100, stop(0, SIGTRAP | 0x80)))
                try:
                    tracer.step()
                except kernel.namespace['Stopping']:
                    assert phase == 'held' and result == -errno.ENOSPC
                    reason, observed = kernel.stopped
                    assert reason == 'disk' and observed['returned'] == -28
                    assert observed['syscall'] == ('write' if nr == 1 else 'pwrite64')
                    assert observed['store'] == 'tmp' and observed['inode'] == 50
                    assert observed['device'] == observed['mountId'] == 1
                    assert observed['stopBeforeNextInstruction'] and kernel.packets == [('stop', {'event': observed})]
                except kernel.namespace['Invalid']:
                    assert phase == 'async' and result == -errno.ENOSPC
                else:
                    assert result != -errno.ENOSPC and not kernel.packets
                    assert tracer.tasks[100]['entry'] is None
                assert tracer.counts['writes'] == (0 if result == -512 else 1)
                kernel.reap()
                assert kernel.closed.count(50) == 1
                cases += 1
    return cases


scenario, arrival = sys.argv[1:3]
if scenario in ['birth-exit', 'exit-first', 'terminal-first']:
    cases = lifecycle(scenario, arrival)
elif scenario == 'anomalies':
    cases = anomalies()
elif scenario == 'exec-migration':
    cases = exec_migration()
elif scenario in ['birth-reuse', 'creator-reuse', 'closure-reuse', 'exec-reuse']:
    cases = tid_reuse(scenario, arrival)
elif scenario == 'unreported-child':
    cases = unreported_child()
elif scenario == 'creator-liveness':
    cases = creator_liveness()
elif scenario in ['write-exit', 'write-terminal']:
    cases = write_death(scenario, arrival, ['held'])
elif scenario in ['async-write-exit', 'async-write-terminal']:
    cases = write_death(scenario[6:], arrival, ['async'])
elif scenario == 'write-controls':
    cases = write_controls()
else:
    cases = progress(scenario)
print(json.dumps({'scenario': scenario, 'arrival': arrival, 'cases': cases}))
