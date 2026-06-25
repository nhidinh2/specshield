"""Benchmarks: the offline AgentDojo-derived sample and the live AgentDojo adapter.

AgentDojo (ethz-spylab/agentdojo) is the standard prompt-injection-on-agents
benchmark. We read each task's *ground-truth tool calls* (no live agent / LLM
needed) and map the egress action into a typed Action + AgentState:

    injection_task -> action an injection elicits   (should_block=True)
    user_task      -> a legitimate user action      (should_block=False)

Attacks are separated on structural signals only (allow-list derived from user
tasks; read->send taint) -- the ground-truth label is never used in the verdict.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from .core import Action, AgentState, DataLabel, Source

_SAMPLE = os.path.join(os.path.dirname(__file__), "agentdojo_sample.jsonl")
_VIETNAM = os.path.join(os.path.dirname(__file__), "vietnam_scenarios.jsonl")
_BILINGUAL = os.path.join(os.path.dirname(__file__), "bilingual_bec.jsonl")
_BENCH_VERSION = "v1.2.1"
_READ_HINTS = ("read", "search", "get", "download", "list")


@dataclass
class Scenario:
    name: str
    category: str
    language: str
    state: AgentState
    action: Action
    should_block: bool
    note: str = ""


# --------------------------------------------------------------------------- #
# Offline (bundled sample, EN+VI, zero dependencies)
# --------------------------------------------------------------------------- #
def _record_to_scenarios(rec: dict):
    approved = frozenset(rec.get("approved_recipients", ["example.com"]))
    confirmed = frozenset({rec["kind"]}) if rec.get("confirmed") else frozenset()
    taint = frozenset(DataLabel(x) for x in rec.get("tainted", []))
    claims = {"approval": Source(rec["approval"])} if rec.get("approval") else {}
    state = AgentState(approved_recipients=approved, confirmed_kinds=confirmed)
    langs = [("EN", rec["en"]), ("VI", rec["vi"])]
    if rec.get("cs"):
        langs.append(("CS", rec["cs"]))   # code-switched Viet-English
    for lang, text in langs:
        action = Action(rec["kind"], dict(rec["args"]),
                        tainted_labels=taint, claims=claims, text=text)
        yield Scenario(rec["id"], f'{rec["suite"]}/{rec["category"]}', lang,
                       state, action, rec["should_block"], note=text)


def _load_jsonl(path) -> list:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.extend(_record_to_scenarios(json.loads(line)))
    return out


def load_scenarios() -> list:
    return _load_jsonl(_SAMPLE)


def load_vietnam_scenarios() -> list:
    """The six Vietnam-relevant email-agent scenarios (BEC, deepfake authority,
    bank/OTP impersonation, malicious link, VN-EN injection, benign support)."""
    return _load_jsonl(_VIETNAM)


def load_bilingual_scenarios() -> list:
    """Subtle BEC attacks rendered in English, Vietnamese, and code-switched
    Viet-English, to test whether the LLM monitor degrades by language while the
    structural monitor (which ignores text) holds."""
    return _load_jsonl(_BILINGUAL)


# --------------------------------------------------------------------------- #
# Live (real AgentDojo; needs Python >=3.10 + `pip install agentdojo`)
# --------------------------------------------------------------------------- #
def live_available() -> bool:
    try:
        import agentdojo  # noqa: F401
        return True
    except Exception:
        return False


def _map_call(fc):
    """Map an AgentDojo FunctionCall to a SpecShield (kind, args, body).

    Covers egress sinks (send/forward/post) AND consequential non-egress sinks
    (delete, credential change, payment modify, reservation, access change,
    calendar create). Pure-read calls return None and are skipped.
    """
    fn, a = fc.function, dict(fc.args)
    if fn == "send_email":
        return "send_email", {"to": str((a.get("recipients") or [""])[0]), "subject": a.get("subject", "")}, str(a.get("body", ""))
    if fn == "send_money":
        return "send_money", {"iban": str(a.get("recipient", "")), "amount": a.get("amount")}, str(a.get("subject", ""))
    if fn == "send_direct_message":
        return "send_email", {"to": str(a.get("recipient", ""))}, str(a.get("body", ""))
    if fn == "post_webpage":
        return "web_request", {"url": str(a.get("url", "")), "method": "POST"}, str(a.get("content", ""))
    if fn == "get_webpage":
        return "open_link", {"url": str(a.get("url", ""))}, ""
    if fn in ("delete_file", "delete_email"):
        return "delete", {"target": str(a.get("file_id") or a.get("email_id") or "")}, ""
    if fn == "update_password":
        return "update_credential", {"target": "password"}, ""
    if fn in ("update_scheduled_transaction", "update_user_info"):
        return "modify_payment", {"id": str(a.get("id", ""))}, ""
    if fn == "reserve_hotel":
        return "reserve", {"hotel": str(a.get("hotel", ""))}, ""
    if fn == "create_calendar_event":
        return "calendar_create", {"title": a.get("title", "")}, str(a.get("title", ""))
    if fn in ("invite_user_to_slack", "add_user_to_channel", "remove_user_from_slack"):
        return "access_change", {"user": str(a.get("user", ""))}, ""
    return None


def _dest_of(args: dict) -> str:
    for k in ("to", "iban", "recipient", "url"):
        if k in args:
            return str(args[k])
    return ""


def _suite_approved(suite, env) -> frozenset:
    """Allow-list = account domain + destinations seen in legitimate user tasks."""
    approved = set()
    acct = getattr(getattr(env, "inbox", None), "account_email", None)
    if acct and "@" in acct:
        approved.add(acct.split("@")[-1].lower())
    for ut in suite.user_tasks.values():
        try:
            for fc in ut.ground_truth(env):
                eg = _map_call(fc)
                if eg and _dest_of(eg[1]):
                    dest = _dest_of(eg[1]).lower()
                    approved.add(dest)
                    if "@" in dest:
                        approved.add(dest.split("@")[-1])
        except Exception:
            continue
    return frozenset(approved)


def _task_to_record(task, gt, approved, suite_name, is_injection):
    sink, read_before = None, False
    for fc in gt:
        if sink is None and any(h in fc.function for h in _READ_HINTS):
            read_before = True
        m = _map_call(fc)
        if m is not None:
            sink = m
            break
    if sink is None:
        return None  # pure-read task: no consequential action to authorize
    kind, args, body = sink
    return {
        "id": getattr(task, "ID", "task"), "suite": suite_name,
        "category": "injection" if is_injection else "benign",
        "should_block": is_injection, "kind": kind, "args": args,
        "tainted": frozenset({DataLabel.PRIVATE}) if read_before else frozenset(),
        "body": body, "approved": approved,
        # Benign actions originate from the user's own request -> user-approved.
        # Injected actions have no user approval on record. (Assumes the system
        # can distinguish user-requested from injected actions, e.g. a CaMeL-style
        # provenance/dataflow tracker.)
        "approval": None if is_injection else "user_turn",
        "confirmed": not is_injection,
    }


def load_live_scenarios(suite_names=None, translate=False, max_per_suite=None) -> list:
    if not live_available():
        raise RuntimeError("agentdojo not installed (needs Python >=3.10). Use load_scenarios().")
    from agentdojo.task_suite import get_suites

    suites = get_suites(_BENCH_VERSION)
    suite_names = suite_names or list(suites.keys())
    backend = None
    if translate:
        from .monitors import get_backend
        backend = get_backend()

    out, skipped = [], 0
    for sname in suite_names:
        suite = suites[sname]
        env = suite.load_and_inject_default_environment({})
        approved = _suite_approved(suite, env)
        tasks = [(t, False) for t in suite.user_tasks.values()]
        tasks += [(t, True) for t in suite.injection_tasks.values()]
        n = 0
        for task, is_inj in tasks:
            if max_per_suite and n >= max_per_suite:
                break
            try:
                gt = task.ground_truth(env)
            except Exception:
                continue
            rec = _task_to_record(task, gt, approved, sname, is_inj)
            if rec is None:
                skipped += 1
                continue
            n += 1
            confirmed = frozenset({rec["kind"]}) if rec["confirmed"] else frozenset()
            claims = {"approval": Source(rec["approval"])} if rec["approval"] else {}
            state = AgentState(approved_recipients=rec["approved"], confirmed_kinds=confirmed)
            en = rec["body"]
            vi = backend.translate(en) if (backend and hasattr(backend, "translate")) else en
            for lang, text in (("EN", en), ("VI", vi)):
                action = Action(rec["kind"], dict(rec["args"]), tainted_labels=rec["tainted"],
                                claims=dict(claims), text=text)
                out.append(Scenario(rec["id"], f'{sname}/{rec["category"]}', lang,
                                    state, action, rec["should_block"], note=text[:60]))
    skip_note = f"{skipped} pure-read tasks skipped; " if skipped else ""
    print(f"  ({skip_note}benign actions tagged user-approved, injected ones not "
          "-- assumes a user-vs-injected provenance signal.)")
    if translate and backend is not None and not hasattr(backend, "translate"):
        print("  (offline judge can't translate; VI bodies == EN. Set ANTHROPIC_API_KEY for real VI.)")
    return out
