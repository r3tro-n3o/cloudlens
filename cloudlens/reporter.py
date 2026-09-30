"""
CloudLens reporter — formats environment summaries and findings as plain
text. No logic lives here, only formatting. If you're tempted to add a
severity check or a filter in this file, it belongs in analyzer.py
instead.
"""


def format_report(env, findings):
    lines = ["CloudLens v0.1", ""]

    lines.append(
        f"Loaded: {len(env['identities'])} identities, "
        f"{len(env['roles'])} roles, "
        f"{len(env['resources'])} resources, "
        f"{len(env['compute'])} compute"
    )
    lines.append("")
    lines.append(f"Attack paths found: {len(findings)}")
    lines.append("")

    for finding in findings:
        parts = [finding["path"][0]]
        for label, node in zip(finding["edge_labels"], finding["path"][1:]):
            parts.append(f"--{label}--> {node}")
        path_str = " ".join(parts)
        lines.append(f"[{finding['severity']}] {path_str}")

    return "\n".join(lines)


def print_report(env, findings):
    print(format_report(env, findings))
