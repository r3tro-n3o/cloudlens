"""
CloudLens analyzer — walks the graph to find attack paths from identities
to sensitive resources.

v0.1 definition of an attack path: any simple path from an identity node
to a resource node where resource["sensitivity"] == "high". Paths to
low-sensitivity resources are legitimate access and are never returned,
even if they exist in the graph — that's the whole point of the
dev-bucket / company-data split in the test data.

Severity is a lookup table, not a formula. Two inputs: path length
(number of edges) and whether the final edge into the resource used an
admin-level action (a wildcard like "s3:*" or "iam:*"). Don't be
tempted to turn this into a weighted score before there's a reason to —
a lookup table is defensible in an interview, a made-up weighted
formula is not.
"""

import sys

import networkx as nx

from loader import load_environment, CloudLensSchemaError
from graph_builder import build_graph


def _is_admin_action(action):
    return action.endswith(":*") or action == "*"


def _has_privilege_escalation(graph, path):
    """True if any edge along the path is a PassRole hop — the step
    where an identity gains access to a role it doesn't natively have."""
    for source, target in zip(path, path[1:]):
        if graph.get_edge_data(source, target).get("label") == "PassRole":
            return True
    return False


def _severity(path_length, final_action, escalated):
    if escalated and _is_admin_action(final_action):
        return "CRITICAL"
    if _is_admin_action(final_action):
        return "HIGH"
    if path_length <= 3:
        return "HIGH"
    return "MEDIUM"


def find_attack_paths(graph, env):
    identity_ids = [i["id"] for i in env["identities"]]
    sensitive_resource_ids = [
        r["id"] for r in env["resources"] if r["sensitivity"] == "high"
    ]

    findings = []

    for identity_id in identity_ids:
        for resource_id in sensitive_resource_ids:
            if identity_id not in graph or resource_id not in graph:
                continue
            try:
                paths = nx.all_simple_paths(graph, identity_id, resource_id)
            except nx.NodeNotFound:
                continue

            for path in paths:
                edge_labels = [
                    graph.get_edge_data(source, target).get("label", "")
                    for source, target in zip(path, path[1:])
                ]
                final_action = edge_labels[-1]
                escalated = _has_privilege_escalation(graph, path)
                severity = _severity(len(path) - 1, final_action, escalated)
                findings.append(
                    {
                        "path": path,
                        "edge_labels": edge_labels,
                        "severity": severity,
                        "final_action": final_action,
                    }
                )

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    return findings


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python analyzer.py <environment.json>")
        sys.exit(1)

    try:
        environment = load_environment(sys.argv[1])
    except CloudLensSchemaError as e:
        print(f"Schema error: {e}")
        sys.exit(1)

    g = build_graph(environment)
    results = find_attack_paths(g, environment)

    print(f"Attack paths found: {len(results)}\n")
    for finding in results:
        parts = [finding["path"][0]]
        for label, node in zip(finding["edge_labels"], finding["path"][1:]):
            parts.append(f"--{label}--> {node}")
        print(f"[{finding['severity']}] {' '.join(parts)}")
