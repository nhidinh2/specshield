"""SpecShield: a deterministic, structural trusted monitor for tool-using AI agents.

A tiny AI-Control evaluation in the email/spreadsheet domain (AgentDojo): the
trusted monitor is a structural policy checker (dataflow taint + provenance +
allow-lists) rather than an LLM -- cheaper, auditable, and un-jailbreakable. We
trace its safety/usefulness Pareto and show where an adaptive attacker beats it.

Layout:
    core.py        types, predicates, policy DSL (the engine)
    monitors.py    LLM backends + the four monitors + metrics
    benchmarks.py  offline sample + live AgentDojo adapter
    cli.py         all reports + dispatch  (python3 -m specshield <command>)
"""

__version__ = "0.2.0"
