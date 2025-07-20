"""Pickle opcode allow-list and analysis."""

import pickletools
from typing import Any

# Safe pickle opcodes that don't execute arbitrary code
SAFE_OPCODES: set[str] = {
    # Basic data types
    "NONE",
    "NEWTRUE",
    "NEWFALSE",
    "INT",
    "BININT",
    "BININT1",
    "BININT2",
    "LONG",
    "LONG1",
    "LONG4",
    "STRING",
    "BINSTRING",
    "SHORT_BINSTRING",
    "BINBYTES",
    "SHORT_BINBYTES",
    "BINBYTES8",
    "BYTEARRAY8",
    "UNICODE",
    "BINUNICODE",
    "SHORT_BINUNICODE",
    "BINUNICODE8",
    "FLOAT",
    "BINFLOAT",

    # Collections
    "EMPTY_LIST",
    "APPEND",
    "APPENDS",
    "LIST",
    "EMPTY_TUPLE",
    "TUPLE",
    "TUPLE1",
    "TUPLE2",
    "TUPLE3",
    "EMPTY_DICT",
    "DICT",
    "SETITEM",
    "SETITEMS",
    "EMPTY_SET",
    "ADDITEMS",
    "FROZENSET",

    # Stack manipulation
    "MARK",
    "STOP",
    "POP",
    "POP_MARK",
    "DUP",
    "MEMO",
    "PUT",
    "BINPUT",
    "LONG_BINPUT",
    "GET",
    "BINGET",
    "LONG_BINGET",

    # Protocol
    "PROTO",
    "FRAME",

    # Safe object construction (for basic types)
    "BUILD",
    "INST",  # Only safe for whitelisted classes
    "OBJ",   # Only safe for whitelisted classes
}

# Dangerous opcodes that can execute arbitrary code
DANGEROUS_OPCODES: set[str] = {
    "GLOBAL",      # Import and call arbitrary functions
    "REDUCE",      # Call arbitrary callables
    "STACK_GLOBAL", # Import from stack
    "EXT1", "EXT2", "EXT4",  # Extension registry calls
}

# Classes that are safe to instantiate
SAFE_CLASSES: set[str] = {
    "builtins.list",
    "builtins.tuple",
    "builtins.dict",
    "builtins.set",
    "builtins.frozenset",
    "builtins.str",
    "builtins.int",
    "builtins.float",
    "builtins.bool",
    "builtins.bytes",
    "builtins.bytearray",
    "collections.OrderedDict",
    "collections.defaultdict",
    "collections.Counter",
    "collections.deque",
    "numpy.ndarray",
    "numpy.dtype",
    "torch.Tensor",
    "torch.nn.parameter.Parameter",
}


def analyze_pickle_opcodes(data: bytes) -> dict[str, Any]:
    """
    Analyze pickle data for dangerous opcodes.
    
    Args:
        data: Raw pickle data
        
    Returns:
        Dictionary with analysis results
    """
    opcodes_found = set()
    dangerous_found = []
    global_imports = []

    try:
        # Parse opcodes
        ops = list(pickletools.genops(data))

        for opcode, arg, pos in ops:
            opcodes_found.add(opcode.name)

            if opcode.name in DANGEROUS_OPCODES:
                dangerous_found.append({
                    "opcode": opcode.name,
                    "position": pos,
                    "arg": arg
                })

            if opcode.name == "GLOBAL" and arg:
                global_imports.append(arg)

    except Exception as e:
        return {
            "error": f"Failed to parse pickle: {e}",
            "is_safe": False
        }

    # Check for unsafe global imports
    unsafe_imports = []
    for imp in global_imports:
        if imp not in SAFE_CLASSES:
            unsafe_imports.append(imp)

    is_safe = (
        len(dangerous_found) == 0 and
        len(unsafe_imports) == 0
    )

    return {
        "is_safe": is_safe,
        "opcodes_found": list(opcodes_found),
        "dangerous_opcodes": dangerous_found,
        "global_imports": global_imports,
        "unsafe_imports": unsafe_imports,
        "total_opcodes": len(ops)
    }
