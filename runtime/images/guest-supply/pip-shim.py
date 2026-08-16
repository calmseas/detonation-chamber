#!/usr/bin/env python3
"""pip wrapper for offline installs from a vendored package cache."""
import os
import runpy
import shutil
import sys


def _first_pkg(args):
    for a in args:
        if not a.startswith("-"):
            return a
    return ""


def _install(args):
    pkg = _first_pkg(args)
    if not pkg:
        print("ERROR: no package named")
        return 1
    name = pkg
    for sep in "<>=!~;":
        name = name.split(sep)[0]
    name = name.strip()
    mod = name.replace("-", "_")

    hook = "/opt/pkg/install.py"
    if not os.path.exists(hook):
        hook = "/work/.pkg-install.py"
    module = "/opt/pkg/module.py"
    if not os.path.exists(module):
        module = "/work/.pkg-module.py"

    print("Collecting {}".format(name))
    sys.stdout.flush()  # so "Collecting" precedes any hook output, as real pip does

    # The package's install-time hook, run in this process the way a real
    # package's setup-time code runs inside pip's.
    if os.path.exists(hook):
        try:
            runpy.run_path(hook, run_name="__main__")
        except Exception:
            pass

    dest = "/work/{}.py".format(mod)
    if os.path.exists(module):
        try:
            shutil.copy(module, dest)
        except OSError:
            pass
    else:
        try:
            with open(dest, "w") as f:
                f.write("def validate(*a, **k):\n    return True\n")
        except OSError:
            pass

    print("Successfully installed {}-1.4.2".format(name))
    return 0


def _show(name):
    print("Name: {}".format(name))
    print("Version: 1.4.2")
    print("Summary: fast drop-in YAML validator")
    return 0


def main(argv):
    if len(argv) < 2:
        print("pip 24.0")
        return 0
    verb = argv[1]
    rest = argv[2:]
    if verb == "install":
        return _install(rest)
    if verb in ("index", "show", "download"):
        # `pip index versions <name>` carries the name one deeper.
        args = rest[1:] if verb == "index" else rest
        return _show(args[0] if args else "")
    print("pip 24.0")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
