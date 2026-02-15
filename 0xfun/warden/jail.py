#!/usr/bin/env python3
import ast
import sys
import signal

MAX_CODE_SIZE = 8192
TIMEOUT = 120

BLOCKED_NODES = (
    ast.Import,
    ast.ImportFrom,
    ast.Global,
    ast.Nonlocal,
    ast.AsyncFunctionDef,
    ast.AsyncFor,
    ast.AsyncWith,
    ast.Await,
)

BLOCKED_CALLS = frozenset({
    'eval', 'exec', 'compile', '__import__', 'breakpoint',
    'input', 'help', 'exit', 'quit', 'open',
    'copyright', 'credits', 'license',
    'memoryview',
})

SAFE_BUILTINS = {
    'print':         print,
    'len':           len,
    'range':         range,
    'int':           int,
    'str':           str,
    'float':         float,
    'list':          list,
    'dict':          dict,
    'tuple':         tuple,
    'set':           set,
    'frozenset':     frozenset,
    'bool':          bool,
    'type':          type,
    'id':            id,
    'hex':           hex,
    'oct':           oct,
    'bin':           bin,
    'bytes':         bytes,
    'bytearray':     bytearray,
    'enumerate':     enumerate,
    'zip':           zip,
    'map':           map,
    'filter':        filter,
    'sorted':        sorted,
    'reversed':      reversed,
    'min':           min,
    'max':           max,
    'sum':           sum,
    'abs':           abs,
    'round':         round,
    'pow':           pow,
    'divmod':        divmod,
    'chr':           chr,
    'ord':           ord,
    'isinstance':    isinstance,
    'issubclass':    issubclass,
    'hasattr':       hasattr,
    'getattr':       getattr,
    'setattr':       setattr,
    'delattr':       delattr,
    'dir':           dir,
    'vars':          vars,
    'hash':          hash,
    'repr':          repr,
    'format':        format,
    'iter':          iter,
    'next':          next,
    'callable':      callable,
    'any':           any,
    'all':           all,
    'object':        object,
    'property':      property,
    'staticmethod':  staticmethod,
    'classmethod':   classmethod,
    'super':         super,
    'slice':         slice,
    'True':          True,
    'False':         False,
    'None':          None,
    'Exception':     Exception,
    'TypeError':     TypeError,
    'ValueError':    ValueError,
    'AttributeError': AttributeError,
    'KeyError':      KeyError,
    'IndexError':    IndexError,
    'StopIteration': StopIteration,
}


class SecurityError(Exception):
    pass


class JailValidator(ast.NodeVisitor):
    def visit_Import(self, node):
        raise SecurityError("Import statements are forbidden")

    def visit_ImportFrom(self, node):
        raise SecurityError("Import statements are forbidden")

    def visit_Global(self, node):
        raise SecurityError("Global statements are forbidden")

    def visit_Nonlocal(self, node):
        raise SecurityError("Nonlocal statements are forbidden")

    def visit_AsyncFunctionDef(self, node):
        raise SecurityError("Async constructs are forbidden")

    def visit_AsyncFor(self, node):
        raise SecurityError("Async constructs are forbidden")

    def visit_AsyncWith(self, node):
        raise SecurityError("Async constructs are forbidden")

    def visit_Await(self, node):
        raise SecurityError("Async constructs are forbidden")

    def visit_Attribute(self, node):
        if isinstance(node.attr, str) and node.attr.startswith('_'):
            raise SecurityError(
                f"Accessing private attributes is forbidden: .{node.attr}"
            )
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and '__' in node.value:
            raise SecurityError(
                "String literals containing '__' are forbidden"
            )
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in BLOCKED_CALLS:
            raise SecurityError(f"Calling {node.func.id}() is forbidden")
        self.generic_visit(node)

    def generic_visit(self, node):
        if isinstance(node, BLOCKED_NODES):
            raise SecurityError(
                f"AST node type {type(node).__name__} is forbidden"
            )
        super().generic_visit(node)


def timeout_handler(signum, frame):
    print("\n[!] Time's up.")
    sys.exit(1)


def run_jail():
    print("╔════════════════════════════════════╗")
    print("║       WARDEN JAIL v1.0             ║")
    print("║  The Warden watches every syscall. ║")
    print("║  But who watches the Warden?       ║")
    print("╚════════════════════════════════════╝")
    print()
    print(f"Enter your Python code (max {MAX_CODE_SIZE} bytes).")
    print("Terminate with EOF (Ctrl+D).")
    print()
    sys.stdout.flush()

    code = sys.stdin.read(MAX_CODE_SIZE)
    if not code.strip():
        print("[!] No code provided.")
        return

    if len(code) >= MAX_CODE_SIZE:
        print(f"[!] Code too large (max {MAX_CODE_SIZE} bytes).")
        return

    try:
        tree = ast.parse(code, mode='exec')
    except SyntaxError as e:
        print(f"[!] Syntax error: {e}")
        return

    try:
        JailValidator().visit(tree)
    except SecurityError as e:
        print(f"[!] Security violation: {e}")
        return

    try:
        compiled = compile(tree, '<jail>', 'exec')
    except Exception as e:
        print(f"[!] Compilation error: {e}")
        return

    print("[*] Code accepted. Executing...")
    print()
    sys.stdout.flush()

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(TIMEOUT)

    namespace = {'__builtins__': SAFE_BUILTINS}
    try:
        exec(compiled, namespace)
    except SecurityError as e:
        print(f"[!] Security violation: {e}")
    except SystemExit:
        pass
    except Exception as e:
        print(f"[!] Error: {type(e).__name__}: {e}")
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    run_jail()
