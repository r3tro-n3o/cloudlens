"""
CloudLens graph builder — turns a loaded environment dict into a
networkx.DiGraph.

Edge types created:
  AssumeRole   identity/compute -> role, from role["trusts"]
  Executes as  compute -> role, from compute["assumed_role"]
  PassRole     role -> compute, when the role can pass a role that the
               compute resource already assumes
  <action>     role -> resource, for any non-PassRole permission whose
               action's service prefix matches the resource's type and
               whose resource field matches the resource id or "*"

v0.1 deliberately does not validate that every id referenced (in
"trusts", "resource" fields, "assumed_role") actually exists elsewhere
in the environment. A dangling reference just means that edge never
gets created — nothing crashes, the path just isn't found. Add explicit
dangling-reference checking later if bad example files start causing
silent "why didn't it find this path" confusion.
"""

import sys

import networkx as nx

from loader import load_environment, CloudLensSchemaError


def _resource_service_prefix(resource_type):
    """'s3_bucket' -> 's3'. Assumes type is '<service>_<noun>'."""
    return resource_type.split("_")[0]


def _action_service_and_op(action):
    """'s3:GetObject' -> ('s3', 'GetObject'). '*' -> ('*', '*')."""
    if action == "*":
        return "*", "*"
    service, _, op = action.partition(":")
    return service, op


def _is_pass_role_action(action):
    service, op = _action_service_and_op(action)
    return service in ("iam", "*") and op in ("PassRole", "*")


def build_graph(env):
    graph = nx.DiGraph()

    for identity in env["identities"]:
        graph.add_node(identity["id"], node_type="identity")

    for role in env["roles"]:
        graph.add_node(role["id"], node_type="role")

    for resource in env["resources"]:
        graph.add_node(
            resource["id"],
            node_type="resource",
            resource_type=resource["type"],
            sensitivity=resource["sensitivity"],
        )

    for compute in env["compute"]:
        graph.add_node(compute["id"], node_type="compute")

    # compute -> role, "this compute already runs as this role"
    compute_by_assumed_role = {}
    for compute in env["compute"]:
        target_role = compute["assumed_role"]
        graph.add_edge(compute["id"], target_role, label="Executes as")
        compute_by_assumed_role.setdefault(target_role, []).append(compute["id"])

    # identity/compute -> role, from trust lists
    for role in env["roles"]:
        for trusted_id in role["trusts"]:
            graph.add_edge(trusted_id, role["id"], label="AssumeRole")

    # role -> resource (direct access) and role -> compute (PassRole)
    for role in env["roles"]:
        for perm in role["permissions"]:
            action = perm["action"]
            resource_ref = perm["resource"]

            if _is_pass_role_action(action):
                if resource_ref == "*":
                    targets = [r["id"] for r in env["roles"]]
                else:
                    targets = [resource_ref]

                for target_role_id in targets:
                    for compute_id in compute_by_assumed_role.get(target_role_id, []):
                        graph.add_edge(role["id"], compute_id, label="PassRole")
                continue

            service, _ = _action_service_and_op(action)
            for resource in env["resources"]:
                type_prefix = _resource_service_prefix(resource["type"])
                if service != type_prefix:
                    continue
                if resource_ref == "*" or resource_ref == resource["id"]:
                    graph.add_edge(role["id"], resource["id"], label=action)

    return graph


def _print_graph(graph):
    print(f"Nodes ({graph.number_of_nodes()}):")
    for node_id, attrs in graph.nodes(data=True):
        print(f"  {node_id}  [{attrs.get('node_type')}]")

    print(f"\nEdges ({graph.number_of_edges()}):")
    for source, target, attrs in graph.edges(data=True):
        print(f"  {source} --{attrs.get('label')}--> {target}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python graph_builder.py <environment.json>")
        sys.exit(1)

    try:
        environment = load_environment(sys.argv[1])
    except CloudLensSchemaError as e:
        print(f"Schema error: {e}")
        sys.exit(1)

    g = build_graph(environment)
    _print_graph(g)
