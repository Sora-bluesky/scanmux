import sys
import os
import json
import sqlite3

sys.stdin.reconfigure(encoding="utf-8")
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

_script = "/assets/node_modules/@openai/codex-security/_bundled_plugin/scripts/workbench_db.py"
_scripts = "/assets/node_modules/@openai/codex-security/_bundled_plugin/scripts/"
_database = "/work/state/workbench.sqlite3"


def install(invocation_id, max_bytes, max_frame_bytes, max_frames):
    previous_trace = sys.gettrace()
    previous_profile = sys.getprofile()
    state = {"failed": False, "sequence": 0, "bytes": 0, "connections": [], "errors": []}

    def write(record_type, **values):
        try:
            state["sequence"] += 1
            frame = (json.dumps({"schema": "scanmux.sdk-python-registration/v1", "type": record_type,
                                 "invocationId": invocation_id, "pid": os.getpid(),
                                 "sequence": state["sequence"], **values}, separators=(",", ":")) + "\n").encode("utf-8")
            state["bytes"] += len(frame)
            if len(frame) - 1 > max_frame_bytes or state["bytes"] > max_bytes or state["sequence"] > max_frames:
                state["failed"] = True
                return
            if os.write(3, frame) != len(frame):
                state["failed"] = True
        except BaseException:
            state["failed"] = True

    def remember(connection):
        if type(connection) is not sqlite3.Connection:
            return
        if not any(item is connection for item in state["connections"]):
            if state["connections"]:
                state["failed"] = True
            else:
                state["connections"].append(connection)

    def owned(frame):
        caller = frame
        while caller is not None:
            if caller.f_code.co_filename == _script and caller.f_code.co_name == "connect":
                if str(caller.f_locals.get("path")) != _database:
                    state["failed"] = True
                    return False
                remember(caller.f_locals.get("connection"))
                return True
            if caller.f_code.co_filename.startswith(_scripts):
                for local in caller.f_locals.values():
                    if any(local is item for item in state["connections"]):
                        return True
            caller = caller.f_back
        return False

    def trace(frame, event, argument):
        try:
            if state["failed"]:
                return trace
            if frame.f_code.co_filename == _script and frame.f_code.co_name == "connect":
                if "path" in frame.f_locals and str(frame.f_locals["path"]) == _database:
                    remember(frame.f_locals.get("connection"))
                    if event == "return":
                        remember(argument)
            if event == "exception" and frame.f_code.co_filename.startswith(_scripts):
                error = argument[1]
                code = getattr(error, "sqlite_errorcode", None)
                if isinstance(error, sqlite3.Error) and type(error).__module__ == "sqlite3" and type(code) is int and owned(frame):
                    if not any(item[0] is error for item in state["errors"]):
                        if len(state["errors"]) >= max_frames:
                            state["failed"] = True
                        else:
                            kind = "full" if code & 255 == 13 else "other"
                            state["errors"].append((error, kind))
                            write("error", kind=kind)
        except BaseException:
            state["failed"] = True
        return trace

    def finish(original_error):
        try:
            if previous_trace is not None or previous_profile is not None:
                state["failed"] = True
            elif sys.gettrace() is trace:
                sys.settrace(previous_trace)
            else:
                state["failed"] = True
            if sys.getprofile() is not previous_profile:
                state["failed"] = True
            other = any(kind == "other" for _, kind in state["errors"])
            full_terminal = not other and any(error is original_error and kind == "full" for error, kind in state["errors"])
            terminal = "normal" if original_error is None else "sqlite_full" if full_terminal else "other"
            write("end", state="unavailable" if state["failed"] else "complete", terminal=terminal)
        except BaseException:
            state["failed"] = True

    try:
        write("ready", python=list(sys.version_info[:3]), traceAbsent=previous_trace is None, profileAbsent=previous_profile is None)
        if previous_trace is None and previous_profile is None:
            sys.settrace(trace)
        else:
            state["failed"] = True
    except BaseException:
        state["failed"] = True
    return finish
