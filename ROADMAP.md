# CloudLens Roadmap

CloudLens is a local-first cloud attack-path analysis tool. It models a cloud
environment as a graph, finds paths an attacker could take from an identity to
a sensitive resource, explains why each path matters, and suggests how to
break it. No live cloud infrastructure required to build, test, or demo it.

Each version below is a real, working, shippable state. Stop at any of them
and you still have something finished, not a half-built feature.

---

## v0.1 — Core engine

**Goal:** prove the core idea works. Given an environment, find real attack
paths.

**Scope:**
- Custom JSON schema for input: `identities`, `roles`, `resources`, `compute`
- `loader.py` — reads and validates the JSON
- `graph_builder.py` — builds a `networkx.DiGraph` from the environment
  - identity → role edge when the role trusts that identity (`AssumeRole`)
  - role → compute edge when compute assumes that role
  - role → resource edge when a role permission matches the resource type
  - role → role edge when `iam:PassRole` creates a path to a more
    privileged role through compute
- `analyzer.py` — `nx.all_simple_paths()` from every identity to every
  resource marked `sensitivity: high`; simple severity lookup table (path
  length + whether the final permission is admin-level)
- `reporter.py` — plain text CLI output, no color, no graphics
- `cli.py` — `cloudlens scan environment.json`
- 2–3 example environment files (`small-startup.json`, `bank-sim.json`),
  each deliberately including both real attack paths **and** legitimate
  low-sensitivity access (e.g. `developer → DevRole → dev-bucket` where
  `dev-bucket` is not marked `sensitivity: high`) — this proves the
  analyzer filters correctly instead of just flagging every reachable path
- Tests covering the graph logic and path-finding

**Out of scope:** Terraform input, `explain`/`simulate`/`defend` commands,
any UI.

**Definition of done:** running `cloudlens scan` against the example files
correctly finds every planted attack path, flags none of the legitimate
low-sensitivity access as an attack path, and produces no other false
positives.

---

## v0.2 — Better analysis

**Goal:** make the tool's judgment more credible, not just its feature count.

**Scope:**
- Wildcard permission matching (`s3:*` matches `s3:GetObject`)
- Resource sensitivity tiers beyond just high/low
- Proper severity lookup table replacing the v0.1 heuristic
- `cloudlens explain PATH-001` — step-by-step reasoning for one path:
  ```
  PATH-001

  Initial identity: developer

  1. developer can assume DevRole
  2. DevRole can pass AdminRole
  3. AdminRole can access sensitive-bucket
  4. sensitive-bucket contains protected data

  Root cause: DevRole has excessive iam:PassRole permission
  ```

**Out of scope:** new input formats, UI.

**Definition of done:** `explain` output reads like something a junior
analyst wrote after actually understanding the chain, not a template fill-in.

---

## v0.3 — Terraform parser

**Goal:** prove the schema was designed right by adding a second input format
without touching the analyzer.

**Scope:**
- `python-hcl2` to read `.tf` files
- Parser converts `aws_iam_role`, `aws_iam_policy`, `aws_s3_bucket`,
  `aws_instance` into the existing internal JSON schema
- `cloudlens terraform ./terraform/`
- At least one realistic multi-file Terraform example to test against

**Definition of done:** the same analyzer and reporter code runs unmodified
against Terraform-derived input as against hand-written JSON.

---

## v0.4 — Remediation / defend mode

**Goal:** turn this from a scanner into something that demonstrates security
engineering.

**Scope:**
- Rule-based remediation suggestions (not AI-generated) tied to the root
  cause identified by `explain`
- `cloudlens defend PATH-001` — shows the fix and the before/after path:
  ```
  BEFORE
  developer → DevRole → PassRole → AdminRole → S3

  AFTER
  developer → DevRole
                   X
                PassRole

  Attack path broken.
  ```

**Definition of done:** for every attack path in your example environments,
there's a specific, correct remediation, not a generic "restrict
permissions" message.

---

## v0.5 — Static visualization

**Goal:** something that looks good as a README screenshot without building
a frontend.

**Scope:**
- `networkx.draw()` + `matplotlib`, or `graphviz` if it renders cleaner
- PNG export of the attack graph, highlighting the discovered path
- Decide here, deliberately, whether a web frontend is worth the time versus
  great CLI output plus static images. Don't drift into it by accident.

**Definition of done:** a graph image good enough to put at the top of the
README.

---

## v1.0 — Polish and ship

**Goal:** portfolio-ready.

**Scope:**
- README with the actual differentiator up front: "finds the paths, not
  just the findings"
- 3+ realistic example environments, including one with a deliberately nasty
  multi-step path
- Full test coverage on graph and analysis logic
- `pyproject.toml` so it installs cleanly
- Demo GIF or short video of the CLI running end to end, including `explain`
  and `defend`

**Definition of done:** you could hand this repo to a stranger and they'd
understand what it does and why it's good within one README scroll.

---

## Someday-maybe pile

Not committed, not scheduled, not version-numbered. Only touch these if
v1.0 actually ships and there's still appetite left.

- **CloudFormation parser** — same idea as the Terraform parser, third input
  format
- **Azure / GCP support** — provider abstraction layer over the internal
  model
- **React dashboard** — interactive graph, click-a-node detail view
- **Live AWS demo mode** — spin up a minimal real lab for a one-time demo
  video, tear down same day
- **Live AWS collector** — a boto3-based input method that queries
  actual deployed IAM roles, policies, and resources and auto-generates
  CloudLens's environment JSON, instead of relying on hand-written JSON
  or static Terraform parsing. Built and tested against LocalStack
  first, since the boto3 calls are identical whether they hit LocalStack
  or a real account, then pointed at real read-only credentials once
  proven. This is not the same thing as "live AWS demo mode" above —
  that's a one-off video, this is a third reusable input method sitting
  alongside the JSON and Terraform loaders. It's also a meaningful
  upgrade over Terraform parsing alone, since Terraform only reflects
  what's declared in code, not what's actually deployed — config drift,
  console-created roles, and manual changes are invisible to a Terraform
  parser but visible to a live collector
- **Synthetic CloudTrail generator + detection/investigation engine** — the
  attack-simulation-and-telemetry idea from the original AWS lab concept,
  rebuilt local-first: simulator emits fake CloudTrail-shaped JSON events,
  a separate detection engine looks for suspicious sequences in them, an
  investigation command reconstructs a timeline. This is genuinely a
  second product bolted onto CloudLens, not a phase of it — treat it as
  the sequel, not part of v1.x.
- **Network modeling** — security groups, subnets, internet exposure, so
  the graph reasons about identity + permissions + network reachability
  together, not IAM alone
- **Authorized/intended access modeling** — an `authorized` flag on
  relationships so CloudLens can eventually tell apart "reachable and
  expected" from "reachable and nobody meant for this to exist." This is
  the real hard problem underneath reachable-vs-attack-path: two identical
  paths in the graph can have opposite security meanings depending on
  intent, and no amount of smarter path-finding fixes that on its own.
  Real tools handle this by comparing against a baseline of intended
  access, not by inferring intent from the graph shape. Worth doing right,
  not worth rushing into v0.1

---

## Why staged this way

Every version above is something you could stop at and still call
finished. The someday-maybe pile exists so ambition has somewhere to go
that isn't blocking v1.0. A fourteen-phase plan where the finish line keeps
moving is how projects die in a half-built state. A five-version plan where
v0.1 already works is how projects actually ship.