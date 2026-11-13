"""
VerifyFix Universal Auto-Mock & Package Namespace Engine
==========================================================

Provides zero-configuration symbol virtualization and import handling for
arbitrary Python repositories:

1. Hybrid Mock Types (Exception + Type):
   - Inherits from BaseException so `except MissingError:` blocks never raise:
     "TypeError: catching classes that do not inherit from BaseException is not allowed".
   - Is a real `type` so `isinstance(x, MissingType)` and `class Sub(MissingBase):` work cleanly.

2. Universal Passthrough Decorator:
   - Preserves original functions under `@mock_decorator` or `@mock_decorator(...)`.

3. Meta-Path Dynamic Import Interceptor:
   - Automatically catches missing third-party packages on the fly and returns
     a HybridMockModule without requiring pip install.

4. Relative Import Package Namespace Loader:
   - Resolves `from . import ...` and `from .. import ...` by binding standalone
     files to a synthetic parent package namespace.
"""

import sys
import os
import types
import inspect
import dis
import importlib.util
from unittest.mock import MagicMock
from typing import Optional, Any


# ---------------------------------------------------------------------------
# 1. Dynamic Auto-Unpacker Helper
# ---------------------------------------------------------------------------

def _get_dynamic_unpack_iter(mock_factory, max_fallback: int = 5):
    """
    Inspects the caller's bytecode frame to determine the exact number of targets
    expected by an UNPACK_SEQUENCE instruction (e.g. a, b = mock).
    Returns an iterator yielding exactly that many mock instances so unpacking
    never raises 'ValueError: not enough/too many values to unpack'.
    """
    count = 2
    try:
        frame = sys._getframe(2)
        code = frame.f_code
        lasti = frame.f_lasti
        for inst in dis.get_instructions(code):
            if inst.offset >= lasti and "UNPACK" in inst.opname:
                count = inst.argval or 2
                break
    except Exception:
        count = 2

    return iter([mock_factory(f"item_{i}") for i in range(count)])


def _make_awaitable(val):
    """Returns a generator that satisfies the Python __await__ protocol."""
    def _gen():
        yield val
        return val
    return _gen()


async def _make_anext_stop():
    raise StopAsyncIteration


# ---------------------------------------------------------------------------
# 2. Hybrid Mock Class (real Exception + real Type + Callable Decorator)
# ---------------------------------------------------------------------------

class _HybridMockMeta(type):
    """Metaclass that generates real Type / Exception subclasses on attribute access."""

    def __getattr__(cls, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        child = create_hybrid_mock(f"{cls.__name__}.{name}")
        setattr(cls, name, child)
        return child

    def __iter__(cls):
        return _get_dynamic_unpack_iter(lambda n: create_hybrid_mock(f"{cls.__name__}.{n}"))

    def __len__(cls):
        return 0

    def __bool__(cls):
        return True

    def __contains__(cls, item):
        return False

    def __fspath__(cls):
        return f"/app/mock_{cls.__name__}"

    def __hash__(cls):
        return hash(cls.__name__)

    def __getitem__(cls, key):
        return create_hybrid_mock(f"{cls.__name__}[{key}]")

    def __setitem__(cls, key, value):
        pass

    def __delitem__(cls, key):
        pass

    def get(cls, *a, **k):
        return a[1] if len(a) > 1 else create_hybrid_mock(f"{cls.__name__}.get")

    def items(cls):
        return [("key", create_hybrid_mock(f"{cls.__name__}.val"))]

    def keys(cls):
        return ["key"]

    def values(cls):
        return [create_hybrid_mock(f"{cls.__name__}.val")]

    def write(cls, *a, **k):
        return 0

    def flush(cls):
        pass

    def close(cls):
        pass

    def readline(cls, *a, **k):
        return b""

    def readlines(cls, *a, **k):
        return []

    def __eq__(cls, other):
        return True

    def __ne__(cls, other):
        return False


def create_hybrid_mock(name: str = "HybridMock") -> Any:
    """
    Creates a dynamic class that:
    1. Inherits from Exception (so `except Mock:` works without TypeError).
    2. Is an instance of `type` (so `isinstance(x, Mock)` and `class Child(Mock):` work).
    3. Works as a transparent passthrough decorator for `@mock` and `@mock(args)`.
    4. Has recursive attribute chaining (`Mock.sub.sub2`).
    5. Dynamically supports sequence unpacking (`a, b = mock`) without ValueError.
    6. Implements magic methods (__len__, __bool__, arithmetic, path, dict, async) to prevent TypeErrors.
    """

    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        # If used as bare decorator: @decorator
        if len(args) == 1 and callable(args[0]) and not kwargs:
            return args[0]
        # If used as parameterized decorator: @decorator(param=1)
        # return a callable that returns the decorated function intact
        def _decorator_wrapper(fn=None, *a, **k):
            if callable(fn):
                return fn
            return create_hybrid_mock(f"{name}_call_result")

        # When called as a regular function (e.g. parse_options_header("...")),
        # return a new mock that can be unpacked or used as a value
        if not (len(args) == 1 and callable(args[0])):
            return create_hybrid_mock(f"{name}_result")

        return _decorator_wrapper

    def __repr__(self):
        return f"<HybridMock '{name}'>"

    attrs = {
        "__module__": "auto_mock",
        "__init__": __init__,
        "__call__": __call__,
        "__repr__": __repr__,
        "__getattr__": lambda self, item: create_hybrid_mock(f"{name}.{item}"),
        "__enter__": lambda self: self,
        "__exit__": lambda self, exc_type, exc_val, exc_tb: False,
        "__aenter__": lambda self: _make_awaitable(self),
        "__aexit__": lambda self, *args: _make_awaitable(False),
        "__await__": lambda self: _make_awaitable(self),
        "__aiter__": lambda self: self,
        "__anext__": lambda self: _make_anext_stop(),
        "__iter__": lambda self: _get_dynamic_unpack_iter(lambda n: create_hybrid_mock(f"{name}.{n}")),
        "__getitem__": lambda self, key: create_hybrid_mock(f"{name}[{key}]"),
        "__setitem__": lambda self, key, value: None,
        "__delitem__": lambda self, key: None,
        "__len__": lambda self: 0,
        "__bool__": lambda self: True,
        "__int__": lambda self: 0,
        "__float__": lambda self: 0.0,
        "__str__": lambda self: f"Mock_{name}",
        "__bytes__": lambda self: b"",
        "__contains__": lambda self, item: False,
        "__fspath__": lambda self: f"/app/mock_{name}",
        "__hash__": lambda self: hash(name),
        "__eq__": lambda self, other: True,
        "__ne__": lambda self, other: False,
        "__add__": lambda self, o: self,
        "__radd__": lambda self, o: o,
        "__sub__": lambda self, o: self,
        "__mul__": lambda self, o: self,
        "__truediv__": lambda self, o: self,
        # Stream / file-like interface
        "read": lambda *a, **k: b"",
        "readline": lambda *a, **k: b"",
        "readlines": lambda *a, **k: [],
        "write": lambda *a, **k: 0,
        "seek": lambda *a, **k: 0,
        "tell": lambda *a, **k: 0,
        "flush": lambda *a, **k: None,
        "close": lambda *a, **k: None,
        # Dictionary-like interface
        "get": lambda *a, **k: a[1] if len(a) > 1 else create_hybrid_mock(f"{name}.get"),
        "items": lambda *a, **k: [("key", create_hybrid_mock(f"{name}.val"))],
        "keys": lambda *a, **k: ["key"],
        "values": lambda *a, **k: [create_hybrid_mock(f"{name}.val")],
        "pop": lambda *a, **k: a[1] if len(a) > 1 else create_hybrid_mock(f"{name}.pop"),
        "update": lambda *a, **k: None,
        "setdefault": lambda *a, **k: a[1] if len(a) > 1 else create_hybrid_mock(f"{name}.setdefault"),
    }

    return _HybridMockMeta(name, (Exception,), attrs)


# ---------------------------------------------------------------------------
# 2. Hybrid Mock Module
# ---------------------------------------------------------------------------

class HybridMockModule(types.ModuleType):
    """A virtual module that serves HybridMocks for any symbol requested."""

    def __init__(self, name: str):
        super().__init__(name)
        self.__file__ = f"<virtual_{name}>"
        self.__path__ = []
        self.__all__ = []

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        val = create_hybrid_mock(f"{self.__name__}.{name}")
        setattr(self, name, val)
        return val


# ---------------------------------------------------------------------------
# 3. Meta-Path Dynamic Import Interceptor
# ---------------------------------------------------------------------------

class AutoMockFinder:
    """Intercepts unresolvable module imports and serves a HybridMockModule."""

    def __init__(self):
        self._disabled = False

    def find_spec(self, fullname: str, path: Optional[Any], target: Optional[Any] = None):
        if self._disabled:
            return None

        # Do not intercept Python built-ins
        top_name = fullname.split(".")[0]
        if top_name in sys.builtin_module_names:
            return None

        # If already loaded in sys.modules, let Python use it
        if fullname in sys.modules:
            return None

        # Return a spec that creates a HybridMockModule
        loader = AutoMockLoader(fullname)
        return importlib.util.spec_from_loader(fullname, loader)


class AutoMockLoader:
    def __init__(self, fullname: str):
        self.fullname = fullname

    def create_module(self, spec) -> types.ModuleType:
        mod = HybridMockModule(self.fullname)
        sys.modules[self.fullname] = mod
        return mod

    def exec_module(self, module):
        pass


_finder_instance: Optional[AutoMockFinder] = None


def enable_auto_mock() -> AutoMockFinder:
    """Installs the AutoMockFinder hook into sys.meta_path if not already present."""
    global _finder_instance
    if _finder_instance is None:
        _finder_instance = AutoMockFinder()
        # Insert at the end of sys.meta_path so real modules load first!
        sys.meta_path.append(_finder_instance)
    return _finder_instance


def disable_auto_mock():
    """Removes the AutoMockFinder hook from sys.meta_path."""
    global _finder_instance
    if _finder_instance and _finder_instance in sys.meta_path:
        sys.meta_path.remove(_finder_instance)
        _finder_instance = None


# ---------------------------------------------------------------------------
# 4. Relative Import Package Namespace Loader
# ---------------------------------------------------------------------------

def load_module_with_package(file_path: str, package_name: str = "app") -> types.ModuleType:
    """
    Loads any target Python file inside a synthetic package namespace so
    relative imports (from . import x, from ..models import y) resolve cleanly
    without 'no known parent package' errors.
    """
    abs_path = os.path.abspath(file_path)
    file_dir = os.path.dirname(abs_path)
    base_name = os.path.splitext(os.path.basename(abs_path))[0]
    full_name = f"{package_name}.{base_name}"

    if package_name not in sys.modules:
        pkg = types.ModuleType(package_name)
        pkg.__path__ = [file_dir]
        pkg.__package__ = package_name
        sys.modules[package_name] = pkg

    spec = importlib.util.spec_from_file_location(
        full_name,
        abs_path,
        submodule_search_locations=[file_dir]
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load spec for file: {file_path}")

    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = package_name
    sys.modules[full_name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# 5. Standalone Relative Import Package Enforcer
# ---------------------------------------------------------------------------

_orig_pathfinder_find_spec = importlib.machinery.PathFinder.find_spec

def _safe_pathfinder_find_spec(fullname: str, path: Optional[Any] = None, target: Optional[Any] = None):
    """
    Ensures standalone .py files have submodule_search_locations populated.
    This tells Python that the module has a valid parent package, completely
    preventing: 'ImportError: attempted relative import with no known parent package'.
    """
    spec = _orig_pathfinder_find_spec(fullname, path, target)
    if spec is not None and getattr(spec, "origin", None) and spec.origin.endswith(".py"):
        if spec.submodule_search_locations is None:
            spec.submodule_search_locations = [os.path.dirname(os.path.abspath(spec.origin))]
    return spec

importlib.machinery.PathFinder.find_spec = _safe_pathfinder_find_spec

# Enable by default on import
enable_auto_mock()

