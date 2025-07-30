import builtins
from types import SimpleNamespace
from core.utils import echo

# stash the real print
_orig_print = builtins.print

# single, global context object
_ctx = SimpleNamespace(to_console=True, to_op=None, world=False)

def set_output_context(to_console: bool=True, to_op: str=None, world_wide: bool=False):
    """Adjust where print() goes for the entire process."""
    _ctx.to_console = to_console
    _ctx.to_op      = to_op
    _ctx.world = world_wide

def _print(*args, sep=' ', end='\n', color=None, **kwargs):
    # build the string
    msg = sep.join(str(a) for a in args)
    # pull from our global context (no AttributeError possible)
    console = _ctx.to_console
    op      = _ctx.to_op
    world = _ctx.world
    echo(msg,
         to_console=console,
         to_op=op,
         world_wide=world,
         color=color,
         _raw_printer=_orig_print,
         end=end)

# override built‑in print for every thread
builtins.print = _print