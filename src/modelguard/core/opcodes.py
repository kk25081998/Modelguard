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

# Opcodes that are potentially dangerous but may be legitimate
POTENTIALLY_DANGEROUS_OPCODES: set[str] = {
    "GLOBAL",      # Import and call functions - dangerous if unsafe imports
    "REDUCE",      # Call callables - dangerous if unsafe callables
    "STACK_GLOBAL", # Import from stack - dangerous if unsafe imports
}

# Opcodes that are always dangerous
ALWAYS_DANGEROUS_OPCODES: set[str] = {
    "EXT1", "EXT2", "EXT4",  # Extension registry calls - always suspicious
}

# Classes that are safe to instantiate
SAFE_CLASSES: set[str] = {
    # Built-in types
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
    
    # Collections
    "collections.OrderedDict",
    "collections.defaultdict",
    "collections.Counter",
    "collections.deque",
    
    # NumPy
    "numpy.ndarray",
    "numpy.dtype",
    "numpy.core.multiarray._reconstruct",
    "numpy.core.multiarray.scalar",
    
    # PyTorch
    "torch.Tensor",
    "torch.nn.parameter.Parameter",
    "torch.Size",
    "torch.dtype",
    "torch.device",
    "torch.storage._TypedStorage",
    "torch.storage._UntypedStorage",
    "torch.FloatStorage",
    "torch.LongStorage",
    "torch.IntStorage",
    "torch.DoubleStorage",
    "torch.ByteStorage",
    "torch.CharStorage",
    "torch.ShortStorage",
    "torch.HalfStorage",
    "torch.BoolStorage",
    "torch._utils._rebuild_tensor_v2",
    "torch._utils._rebuild_parameter",
    
    # Scikit-learn
    "sklearn.linear_model._base.LinearRegression",
    "sklearn.linear_model._logistic.LogisticRegression",
    "sklearn.ensemble._forest.RandomForestClassifier",
    "sklearn.ensemble._forest.RandomForestRegressor",
    "sklearn.svm._classes.SVC",
    "sklearn.svm._classes.SVR",
    "sklearn.tree._classes.DecisionTreeClassifier",
    "sklearn.tree._classes.DecisionTreeRegressor",
    "sklearn.preprocessing._data.StandardScaler",
    "sklearn.preprocessing._data.MinMaxScaler",
    "sklearn.preprocessing._label.LabelEncoder",
    "sklearn.model_selection._split.train_test_split",
    
    # Common ML libraries
    "joblib.numpy_pickle.NumpyArrayWrapper",
    "joblib.numpy_pickle.ZNDArrayWrapper",
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
    always_dangerous_found = []
    potentially_dangerous_found = []
    global_imports = []
    stack_global_imports = []

    try:
        # Parse opcodes and track stack for STACK_GLOBAL
        ops = list(pickletools.genops(data))
        stack = []

        for opcode, arg, pos in ops:
            opcodes_found.add(opcode.name)

            # Check for always dangerous opcodes
            if opcode.name in ALWAYS_DANGEROUS_OPCODES:
                always_dangerous_found.append({
                    "opcode": opcode.name,
                    "position": pos,
                    "arg": arg
                })

            # Check for potentially dangerous opcodes
            if opcode.name in POTENTIALLY_DANGEROUS_OPCODES:
                potentially_dangerous_found.append({
                    "opcode": opcode.name,
                    "position": pos,
                    "arg": arg
                })

            # Track stack for STACK_GLOBAL analysis
            if opcode.name == "SHORT_BINUNICODE" and arg:
                stack.append(arg)
            elif opcode.name == "STACK_GLOBAL":
                # STACK_GLOBAL pops module and name from stack
                if len(stack) >= 2:
                    name = stack.pop()
                    module = stack.pop()
                    import_name = f"{module}.{name}"
                    stack_global_imports.append(import_name)
                    global_imports.append(import_name)
                else:
                    # Can't determine what was imported
                    stack_global_imports.append("UNKNOWN_STACK_GLOBAL")
                    global_imports.append("UNKNOWN_STACK_GLOBAL")

            # Collect regular global imports
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
        if imp not in SAFE_CLASSES and not _is_safe_import(imp):
            unsafe_imports.append(imp)

    # Only flag as dangerous if:
    # 1. Always dangerous opcodes are present, OR
    # 2. Potentially dangerous opcodes are used with unsafe imports
    dangerous_opcodes = always_dangerous_found.copy()
    
    # Only add potentially dangerous opcodes if they're used with unsafe imports
    if unsafe_imports:
        dangerous_opcodes.extend(potentially_dangerous_found)

    is_safe = (
        len(always_dangerous_found) == 0 and
        len(unsafe_imports) == 0
    )

    return {
        "is_safe": is_safe,
        "opcodes_found": list(opcodes_found),
        "dangerous_opcodes": dangerous_opcodes,
        "global_imports": global_imports,
        "stack_global_imports": stack_global_imports,
        "unsafe_imports": unsafe_imports,
        "total_opcodes": len(ops)
    }


def _is_safe_import(import_name: str) -> bool:
    """Check if an import is safe based on patterns."""
    if import_name == "UNKNOWN_STACK_GLOBAL":
        return False
    
    # Known dangerous imports
    dangerous_patterns = [
        "os.system", "os.popen", "os.exec", "os.spawn",
        "subprocess.", "eval", "exec", "compile",
        "__import__", "importlib",
        "urllib.", "requests.", "http.",
        "socket.", "ftplib.", "smtplib.",
        "nt.system", "posix.system"
    ]
    
    for pattern in dangerous_patterns:
        if pattern in import_name:
            return False
    
    # Known safe patterns for ML
    safe_patterns = [
        "numpy.", "torch.", "sklearn.", "tensorflow.",
        "collections.", "builtins.", "joblib.",
        "_pickle.", "copyreg.", "functools."
    ]
    
    for pattern in safe_patterns:
        if import_name.startswith(pattern):
            return True
    
    # Handle attribute access patterns (like "coef_.dtype")
    # These are usually safe as they're just accessing object attributes
    if "." in import_name and not import_name.startswith(("os.", "subprocess.", "sys.")):
        parts = import_name.split(".")
        # If it looks like attribute access on a safe object, allow it
        if len(parts) == 2 and (
            parts[0].endswith("_") or  # Common ML attribute pattern
            parts[1] in ["dtype", "shape", "size", "ndim", "scalar"]  # Common NumPy attributes
        ):
            return True
    
    return False
