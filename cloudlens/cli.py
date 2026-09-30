"""
CloudLens CLI — entry point.

v0.1 has one subcommand: `scan`. Later subcommands (`explain`, `defend`,
`terraform`) are siblings of `scan`, not replacements — add them as
their own subparsers, don't grow `scan` to do more than scanning.
"""

import argparse
import sys

from loader import load_environment, CloudLensSchemaError
from graph_builder import build_graph
from analyzer import find_attack_paths
from reporter import print_report


def main():
    parser = argparse.ArgumentParser(
        prog="cloudlens",
        description="Local-first cloud attack-path analysis.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan", help="Find attack paths in a CloudLens environment file"
    )
    scan_parser.add_argument("environment", help="Path to environment JSON file")

    args = parser.parse_args()

    if args.command == "scan":
        try:
            env = load_environment(args.environment)
        except CloudLensSchemaError as e:
            print(f"Schema error: {e}")
            sys.exit(1)

        graph = build_graph(env)
        findings = find_attack_paths(graph, env)
        print_report(env, findings)


if __name__ == "__main__":
    main()
