"""
CloudLens loader — reads and validates a CloudLens environment JSON file.

v0.1 scope: structural validation only. Checks the top-level keys exist
and are lists, and that entries have the fields the graph builder needs.
Doesn't validate permission syntax or catch dangling references yet
(e.g. a role that "trusts" an identity that doesn't exist) — that's a
deliberate v0.1 cut, not an oversight. Add it once the graph builder is
solid enough that you know what errors actually show up in practice.
"""

import json
import sys


REQUIRED_KEYS = ["identities", "roles", "resources", "compute"]


class CloudLensSchemaError(Exception):
    """Raised when an environment file doesn't match the expected shape."""


def load_environment(path):
    """
    Load and structurally validate a CloudLens environment JSON file.

    Returns the parsed dict on success. Raises CloudLensSchemaError with
    a specific, human-readable message on any structural problem, so the
    CLI can print something useful instead of a raw traceback.
    """
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise CloudLensSchemaError(f"No such file: {path}")
    except json.JSONDecodeError as e:
        raise CloudLensSchemaError(f"Invalid JSON in {path}: {e}")

    if not isinstance(data, dict):
        raise CloudLensSchemaError(
            f"{path} must contain a JSON object at the top level, "
            f"got {type(data).__name__}"
        )

    for key in REQUIRED_KEYS:
        if key not in data:
            raise CloudLensSchemaError(f"Missing required top-level key: '{key}'")
        if not isinstance(data[key], list):
            raise CloudLensSchemaError(
                f"'{key}' must be a list, got {type(data[key]).__name__}"
            )

    _validate_identities(data["identities"])
    _validate_roles(data["roles"])
    _validate_resources(data["resources"])
    _validate_compute(data["compute"])

    return data


def _validate_identities(identities):
    for i, identity in enumerate(identities):
        if "id" not in identity:
            raise CloudLensSchemaError(f"identities[{i}] is missing 'id'")


def _validate_roles(roles):
    for i, role in enumerate(roles):
        if "id" not in role:
            raise CloudLensSchemaError(f"roles[{i}] is missing 'id'")
        if "trusts" not in role or not isinstance(role["trusts"], list):
            raise CloudLensSchemaError(
                f"roles[{i}] ('{role.get('id', '?')}') must have a 'trusts' list"
            )
        if "permissions" not in role or not isinstance(role["permissions"], list):
            raise CloudLensSchemaError(
                f"roles[{i}] ('{role.get('id', '?')}') must have a "
                f"'permissions' list"
            )
        for j, perm in enumerate(role["permissions"]):
            if "action" not in perm or "resource" not in perm:
                raise CloudLensSchemaError(
                    f"roles[{i}] ('{role.get('id', '?')}') permissions[{j}] "
                    f"must have both 'action' and 'resource'"
                )


def _validate_resources(resources):
    for i, resource in enumerate(resources):
        if "id" not in resource:
            raise CloudLensSchemaError(f"resources[{i}] is missing 'id'")
        if "type" not in resource:
            raise CloudLensSchemaError(
                f"resources[{i}] ('{resource.get('id', '?')}') is missing 'type'"
            )
        if "sensitivity" not in resource:
            raise CloudLensSchemaError(
                f"resources[{i}] ('{resource.get('id', '?')}') is missing "
                f"'sensitivity'"
            )


def _validate_compute(compute):
    for i, item in enumerate(compute):
        if "id" not in item:
            raise CloudLensSchemaError(f"compute[{i}] is missing 'id'")
        if "assumed_role" not in item:
            raise CloudLensSchemaError(
                f"compute[{i}] ('{item.get('id', '?')}') is missing "
                f"'assumed_role'"
            )


if __name__ == "__main__":
    # quick manual check: python loader.py path/to/environment.json
    if len(sys.argv) != 2:
        print("usage: python loader.py <environment.json>")
        sys.exit(1)

    try:
        env = load_environment(sys.argv[1])
    except CloudLensSchemaError as e:
        print(f"Schema error: {e}")
        sys.exit(1)

    print(
        f"Loaded: {len(env['identities'])} identities, "
        f"{len(env['roles'])} roles, "
        f"{len(env['resources'])} resources, "
        f"{len(env['compute'])} compute"
    )
