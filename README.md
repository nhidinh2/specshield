# SpecShield

A deterministic, structural **trusted monitor** for tool-using AI agents: it
authorizes each proposed tool action by inspecting typed fields, dataflow **taint**,
and **provenance** — never the payload text — so it is cheap, auditable,
un-jailbreakable, and language-agnostic. Evaluated as a small AI-Control study in the
email/spreadsheet setting (AgentDojo).

## Read this first

**[REPORT.md](REPORT.md)** is the full, self-contained writeup — problem, methods,
results, limits, references [S1–S16], and (Appendix D) the scenario→documented-attack
coverage map.

## Run it

Stdlib only, runs offline:

```bash
python3 -m specshield test        # smoke tests
python3 -m specshield demo        # one injection, English vs Vietnamese
python3 -m specshield invariant   # provenance-as-guarantee: enforcement + cost
python3 -m specshield provnoise   # safety/usefulness vs provenance ACCURACY (central result)
python3 -m specshield control     # safety/usefulness Pareto + adaptive attacker + cost
python3 -m specshield attacker    # laundering-effort frontier + optimizing attacker
python3 -m specshield bilingual   # LLM-monitor safety EN/VI/code-switched vs structural
python3 -m specshield redteam     # attacks built to break the structural checker
```

Live AgentDojo + real model (`pip install agentdojo anthropic`, Python ≥3.10, set
`ANTHROPIC_API_KEY`):

```bash
python3 -m specshield provnoise --live   # 75-action provenance curve (no key needed)
python3 -m specshield control  --live
python3 -m specshield attacker --live
SPECSHIELD_OLLAMA_MODEL=qwen2.5:3b python3 -m specshield bilingual   # small/edge model
```

## Layout

| file | role |
|------|------|
| `core.py` | typed `Action`/`AgentState`, structural predicates, policy DSL |
| `monitors.py` | LLM backends (heuristic / Anthropic / Ollama) + the four monitors + metrics |
| `benchmarks.py` | offline EN/VI sample + live AgentDojo adapter |
| `cli.py` | all reports + dispatch |
| `*.jsonl` | bundled scenarios (AgentDojo sample, Vietnam, bilingual BEC) |

The typed `Action` carries `tainted_labels` (did PRIVATE data flow in?) and `claims`
(provenance of any "approval") — the structural signals the monitor reads instead of
free text. See **[REPORT.md](REPORT.md)** for all results, CIs, and honest limits.
