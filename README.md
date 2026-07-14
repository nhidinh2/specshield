# SpecShield

A **structural trusted monitor** for tool-using AI agents. Instead of reading an
action's text (like an LLM monitor), SpecShield authorizes each proposed tool call
from *typed fields, dataflow taint, and the provenance of any "approval"* — making it
language-agnostic, auditable, and free of per-action model cost.

📄 **Paper:** [SpecShield: A Structural Trusted Monitor for Tool-Using AI Agents](./specshield.pdf)

## The idea

Most AI safety moderates what a model *says*. SpecShield governs what an agent *does*.
An agent that reads untrusted content (emails, documents, web pages) and then acts
through tools is vulnerable to prompt injection — a malicious payload can make it
exfiltrate data, move money, or expose credentials via a tool call whose text looks
perfectly benign.

SpecShield enforces a single invariant:

> *Untrusted-instructed content may not trigger a money-moving, credential-exposing, or
> PRIVATE→external action without trusted user approval.*

It checks this with a few deterministic predicates (recipient allow-list, no
PRIVATE→external dataflow, trusted approval provenance, non-destructive shell,
untrusted-destination backstop) and can optionally defer the uncertain cases to an LLM
monitor via a cheap **gated** controller.

## What it shows

- On AgentDojo it enforces the invariant on every relevant attack at ~zero cost to
  benign tasks — **conditional on a provenance signal**.
- Safety degrades *gracefully* (not catastrophically) as that provenance signal gets
  noisier, because the monitor combines several independent checks.
- Under an optimizing attacker, the structural and LLM monitors fail in *disjoint*
  ways, so a gated hybrid holds where either alone breaks.

The takeaway: structural authorization doesn't *solve* prompt injection so much as
*relocate* it to a measurable provenance problem.

## Quick start

Everything runs offline with the Python standard library:

```bash
python3 -m specshield test       # run the test suite
python3 -m specshield demo       # one injection, English vs Vietnamese
python3 -m specshield agentdojo  # leak / false-block across suites (EN + VI)
python3 -m specshield control    # safety/usefulness Pareto + adaptive attacker
python3 -m specshield attacker   # attacker-effort frontier
python3 -m specshield provenance # two-axis provenance-corruption curve (random
                                 # vs targeted) with cluster-bootstrap CIs
python3 -m specshield multistep  # taint propagation across a trajectory
python3 -m specshield semantic   # disjoint failure: text-only attacks
python3 -m specshield redteam    # known limits
```

Add `--vietnam` to `agentdojo`/`control`/`attacker` for the Vietnam scenarios.

Live AgentDojo and real-model runs need extra dependencies:

```bash
pip install agentdojo anthropic      # Python >= 3.10
export ANTHROPIC_API_KEY=...
python3 -m specshield agentdojo --live --translate
```

## Layout

| file | purpose |
|---|---|
| `core.py` | typed action model and policy engine |
| `monitors.py` | structural, LLM, hybrid, and gated monitors |
| `trajectory.py` | multi-step taint propagation across a trajectory |
| `benchmarks.py` | evaluation harness |
| `cli.py` | command-line entry points |
| `*.jsonl` | bundled sample / scenario data |

## Status

Research prototype in the email / spreadsheet / banking / slack / travel suites.
Single-step authorization plus a multi-step taint tracker (`trajectory.py`,
`multistep`). Provenance is corrupted synthetically (`provenance`); a real
(noisy) end-to-end provenance tracker, correlated-error models, and closing the
allow-listed-alias laundering path are open work.
