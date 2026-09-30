# CloudLens

A local-first cloud attack-path analyzer. It models a cloud environment as
a graph and finds the paths an attacker could actually take from an
identity to a sensitive resource, not just a list of misconfigurations
sitting in isolation.

No AWS account, no cloud spend, no infrastructure to stand up. The whole
thing runs on JSON files and your laptop.

## Why this is different from a misconfiguration scanner

Most scanners tell you:

```
❌ S3 bucket publicly readable
❌ IAM role has excessive permissions
❌ Security group too permissive
```

Three findings, no relationship between them, no sense of which ones
actually matter together. CloudLens asks a different question: **can
these individual weaknesses be chained into something exploitable?**

```
$ python3 cloudlens/cli.py scan examples/bank-sim.json

CloudLens v0.1

Loaded: 3 identities, 4 roles, 4 resources, 2 compute

Attack paths found: 4

[CRITICAL] contractor --AssumeRole--> ContractorRole --PassRole--> EC2Instance --AssumeRole--> OpsRole --s3:*--> customer-pii
[CRITICAL] contractor --AssumeRole--> ContractorRole --PassRole--> EC2Instance --AssumeRole--> OpsRole --PassRole--> LambdaFunc --AssumeRole--> AdminRole --s3:*--> core-banking-db
[CRITICAL] junior-dev --AssumeRole--> AdminRole --PassRole--> EC2Instance --AssumeRole--> OpsRole --s3:*--> customer-pii
[HIGH] junior-dev --AssumeRole--> AdminRole --s3:*--> core-banking-db
```

That third finding wasn't hand-designed into the test data. It's the
graph logic discovering, on its own, that a role with `iam:*` doesn't
just have its own listed permissions, it can pass *any other role* in
the environment too. A junior developer directly trusted by an
over-permissioned admin role inherits that role's entire blast radius,
not just its face-value permissions. That's the kind of thing a
checklist-based scanner misses and a graph-based one finds for free.

## How it works

1. You describe an environment as JSON: identities, roles (with trust
   relationships and permissions), resources, and compute
2. CloudLens builds a directed graph — identities and compute resources
   connect to the roles they can assume, roles connect to the resources
   their permissions reach, and `iam:PassRole` permissions create edges
   toward whatever compute resource already runs as the target role
3. It searches for every path from an identity to a resource marked
   `sensitivity: high`
4. Each path gets a severity: **CRITICAL** if it required a privilege
   escalation step (a `PassRole` hop) to reach admin-level access,
   **HIGH** if it reaches admin-level access directly or the path is
   short, **MEDIUM** otherwise

Reachability isn't the same thing as a finding. A role reaching a
low-sensitivity resource through a completely ordinary permission is
expected behavior, not a vulnerability — CloudLens only flags paths that
end at something marked sensitive, and the test data is built specifically
to prove it doesn't cry wolf on the legitimate paths sitting right next
to the real ones.

## Quickstart

```bash
git clone <your-repo-url>
cd cloudlens
pip install -r requirements.txt

python3 cloudlens/cli.py scan examples/small-startup.json
python3 cloudlens/cli.py scan examples/bank-sim.json
```

Run the tests:

```bash
pytest tests/test_analyzer.py -v
```

## Writing your own environment

```json
{
  "identities": [{"id": "developer", "type": "user"}],
  "roles": [
    {
      "id": "DevRole",
      "trusts": ["developer"],
      "permissions": [
        {"action": "s3:GetObject", "resource": "dev-bucket"},
        {"action": "iam:PassRole", "resource": "AdminRole"}
      ]
    }
  ],
  "resources": [
    {"id": "dev-bucket", "type": "s3_bucket", "sensitivity": "low"}
  ],
  "compute": []
}
```

- `trusts` on a role lists which identities or compute resources can
  assume it
- `permissions` is a flat list of `{action, resource}` pairs — use
  `"resource": "*"` for a wildcard, and the action's service prefix
  (`s3`, `iam`) has to match the resource's type prefix (`s3_bucket`) to
  create an edge
- `iam:PassRole` (and `iam:*`, which implies it) doesn't connect
  directly to the target role — it connects to whichever compute
  resource already has that role set as `assumed_role`, since passing a
  role only matters if something actually picks it up

## Project status

This is v0.1: the core graph engine, CLI, and text reporting. No
Terraform input yet, no `explain`/`defend` commands, no visualization.
See [ROADMAP.md](ROADMAP.md) for what's planned and, just as
importantly, what's deliberately being held off until later.

## Tech stack

Python, [NetworkX](https://networkx.org/) for the graph engine, pytest
for tests. That's it — zero cloud spend to build, test, or demo.
