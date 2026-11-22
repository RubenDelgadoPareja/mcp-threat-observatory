"""Behaviour observation hook for Python MCP servers.

Injected by putting this file's directory on PYTHONPATH: Python imports
``sitecustomize`` at startup, before the server module runs.

Two mechanisms, for two different reasons:

* ``sys.addaudithook`` sees name resolution, connections, file opens and child
  processes. It is installed by the interpreter and cannot be removed at
  runtime.
* ``socket.socket.send/sendall/sendto`` are monkeypatched because audit events
  do not carry the bytes being written, and a canary in the payload is the
  strongest evidence this collector can produce.

Both are observation, not containment. C extensions, ``ctypes`` and a spawned
non-Python process can bypass them. The network namespace is the boundary.
"""

import json
import os
import re
import socket as _socket
import sys
import threading
import time

_LOG = os.environ.get("MCPOBS_BEHAVIOUR_LOG")

if _LOG:
    _CANARY = re.compile(r"CANARY-[0-9a-f]{16}")
    _SENSITIVE = re.compile(r"(/\.ssh/|/\.aws/|/\.npmrc$|(^|/)\.env$)")
    _busy = False
    _lock = threading.Lock()
    _targets = {}

    def _now():
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z"

    def _emit(event):
        """Append one JSON line. Re-entrant calls are dropped, not queued.

        Writing the log fires the ``open`` audit event, which would call this
        function again. The guard is what stops that from recursing.
        """
        global _busy
        with _lock:
            if _busy:
                return
            _busy = True
        try:
            event["at"] = _now()
            with open(_LOG, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            pass
        finally:
            with _lock:
                _busy = False

    def _split_address(address):
        if isinstance(address, tuple) and len(address) >= 2:
            host = address[0]
            port = address[1]
            return (
                str(host) if host is not None else None,
                port if isinstance(port, int) else None,
            )
        if isinstance(address, bytes):
            return (address.decode("utf-8", "ignore"), None)
        if isinstance(address, str):
            return (address, None)
        return (None, None)

    def _canary_ids(data):
        try:
            if isinstance(data, (bytes, bytearray, memoryview)):
                text = bytes(data).decode("utf-8", "ignore")
            elif isinstance(data, str):
                text = data
            else:
                return []
        except Exception:
            return []
        return sorted(set(_CANARY.findall(text)))

    def _is_read_mode(mode):
        if not isinstance(mode, str):
            return False
        return not any(flag in mode for flag in ("w", "a", "x", "+"))

    def _audit(event, args):
        try:
            if event == "socket.getaddrinfo":
                host = args[0] if args else None
                if host is not None:
                    _emit({"type": "dns.lookup", "host": str(host)})

            elif event == "socket.connect":
                sock = args[0] if args else None
                address = args[1] if len(args) > 1 else None
                host, port = _split_address(address)
                try:
                    _targets[id(sock)] = (host, port)
                except Exception:
                    pass
                _emit({"type": "net.connect", "host": host, "port": port})

            elif event == "open":
                path = args[0] if args else None
                mode = args[1] if len(args) > 1 else "r"
                if _is_read_mode(mode) and isinstance(path, (str, bytes)):
                    rendered = path.decode("utf-8", "ignore") if isinstance(path, bytes) else path
                    if _SENSITIVE.search(rendered):
                        _emit({"type": "fs.read", "path": rendered})

            elif event in ("subprocess.Popen", "os.system"):
                command = args[0] if args else ""
                _emit({"type": "process.spawn", "detail": str(command)[:160]})

        except Exception:
            # An observation failure must never break the server.
            pass

    def _wrap(original, name):
        def wrapper(self, data, *args, **kwargs):
            ids = _canary_ids(data)
            if ids:
                host, port = _targets.get(id(self), (None, None))
                if name == "sendto" and args:
                    host, port = _split_address(args[-1])
                try:
                    size = len(data)
                except Exception:
                    size = None
                _emit(
                    {
                        "type": "net.write",
                        "host": host,
                        "port": port,
                        "canaryIds": ids,
                        "bytes": size,
                    }
                )
            return original(self, data, *args, **kwargs)

        return wrapper

    def _patch_socket():
        for name in ("send", "sendall", "sendto"):
            original = getattr(_socket.socket, name, None)
            if original is None:
                continue
            setattr(_socket.socket, name, _wrap(original, name))

    def _install():
        _patch_socket()
        sys.addaudithook(_audit)

    try:
        _install()
    except Exception:
        pass
