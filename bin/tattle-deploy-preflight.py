#!/usr/bin/env python3
"""Validate admission-state deployment requirements without contacting Cloudflare."""
import pathlib
import sys

try:
    import tomllib
except ImportError:
    print("tattle: deploy preflight requires Python 3.11 or newer (tomllib); install a current Python and ensure python3 selects it", file=sys.stderr)
    sys.exit(1)

EXAMPLE = '''Required private wrangler.toml configuration (retain your existing migration history;
use a new, unique migration tag when adding the SQLite class):

[[durable_objects.bindings]]
name = "HOST_GATE"
class_name = "HostGate"

[[migrations]]
tag = "v1-host-gate"
new_sqlite_classes = ["HostGate"]
'''


def validate(config):
    main = config.get("main")
    if not isinstance(main, str) or not main.strip():
        raise ValueError("set main to the worker entrypoint that exports HostGate")
    durable = config.get("durable_objects", {})
    if not isinstance(durable, dict) or not isinstance(durable.get("bindings", []), list):
        raise ValueError("durable_objects.bindings must be an array of binding tables")
    bindings = durable.get("bindings", [])
    if any(not isinstance(binding, dict) for binding in bindings):
        raise ValueError("durable_objects.bindings must contain binding tables")
    gates = [binding for binding in bindings if binding.get("name") == "HOST_GATE"]
    if len(gates) != 1 or gates[0].get("class_name") != "HostGate" or "script_name" in gates[0]:
        raise ValueError("configure exactly one local HOST_GATE binding with class_name = \"HostGate\" (no script_name)")
    migrations = config.get("migrations", [])
    if not isinstance(migrations, list):
        raise ValueError("migrations must be an array of migration tables")
    classes, tags = {}, set()
    def strings(migration, key):
        values = migration.get(key, [])
        if not isinstance(values, list) or any(not isinstance(value, str) or not value for value in values):
            raise ValueError(f"migration {key} must be an array of class names")
        return values
    for migration in migrations:
        if not isinstance(migration, dict):
            raise ValueError("migrations must contain migration tables")
        tag = migration.get("tag")
        if not isinstance(tag, str) or not tag or tag in tags:
            raise ValueError("each migration requires a unique, nonempty tag")
        tags.add(tag)
        touched = set()
        def touch(name):
            if name in touched:
                raise ValueError(f"migration {tag!r} has conflicting operations for {name}")
            touched.add(name)
        for key, storage in (("new_classes", "key-value"), ("new_sqlite_classes", "sqlite")):
            for name in strings(migration, key):
                touch(name)
                if name in classes:
                    raise ValueError(f"migration {tag!r} recreates existing class {name}")
                classes[name] = storage
        renamed = migration.get("renamed_classes", [])
        transferred = migration.get("transferred_classes", [])
        if not isinstance(renamed, list) or not isinstance(transferred, list):
            raise ValueError("migration renamed_classes and transferred_classes must be arrays")
        for rename in renamed:
            if not isinstance(rename, dict) or any(not isinstance(rename.get(key), str) or not rename[key] for key in ("from", "to")):
                raise ValueError("migration renames require nonempty from and to class names")
            source, target = rename["from"], rename["to"]
            touch(source); touch(target)
            if source not in classes or target in classes:
                raise ValueError(f"migration {tag!r} has an invalid class rename {source} -> {target}")
            classes[target] = classes.pop(source)
        for transfer in transferred:
            if not isinstance(transfer, dict) or not isinstance(transfer.get("to"), str) or not transfer["to"]:
                raise ValueError("migration transfers require a destination class name")
            target = transfer["to"]
            touch(target)
            if target in classes:
                raise ValueError(f"migration {tag!r} transfers into existing class {target}")
            classes[target] = "transferred (SQLite not established locally)"
        for name in strings(migration, "deleted_classes"):
            touch(name)
            if name not in classes:
                raise ValueError(f"migration {tag!r} deletes unknown class {name}")
            del classes[name]
    if classes.get("HostGate") != "sqlite":
        raise ValueError("migration history must establish HostGate with new_sqlite_classes and leave that class present; check deletions, renames, and conflicting new_classes")


try:
    with pathlib.Path(sys.argv[1]).open("rb") as source:
        validate(tomllib.load(source))
except (OSError, ValueError, TypeError, KeyError) as error:
    print(f"tattle: deploy preflight failed: {error}\n\n{EXAMPLE}", file=sys.stderr)
    sys.exit(1)
