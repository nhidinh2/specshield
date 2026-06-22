"""Core engine: typed actions, structural predicates, and the policy DSL.

Combines the data model (Action/AgentState), the predicates that inspect
structured fields + dataflow + provenance, and the deny-overrides policy
aggregation that yields ALLOW / ASK_USER / REVIEW / BLOCK.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
class DataLabel(str, Enum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"


class Source(str, Enum):
    """Provenance of a claim the agent relies on."""
    USER_TURN = "user_turn"        # trusted: the real user said it
    TOOL_OUTPUT = "tool_output"    # semi-trusted
    INJECTED_DOC = "injected_doc"  # untrusted: came from retrieved/external content


@dataclass(frozen=True, eq=False)
class Action:
    """A structured tool call. `tainted_labels` is dataflow (did PRIVATE data
    flow in?), `claims` is provenance (where did an 'approval' come from?), and
    `text` is the free-text payload that only fragile baselines read."""
    kind: str
    args: dict = field(default_factory=dict)
    tainted_labels: frozenset = frozenset()
    claims: dict = field(default_factory=dict)
    text: str = ""


@dataclass(frozen=True)
class AgentState:
    approved_recipients: frozenset = frozenset()   # allow-listed addresses / domains / IBANs
    approved_attendees: frozenset = frozenset()
    confirmed_kinds: frozenset = frozenset()        # action kinds the user explicitly confirmed


# --------------------------------------------------------------------------- #
# Predicates   (ok: True=satisfied, False=violated, None=ABSTAIN)
# --------------------------------------------------------------------------- #
ABSTAIN = None


@dataclass
class PredResult:
    ok: Optional[bool]
    reason: str
    formal: bool          # True if decided structurally (language-agnostic)


Predicate = Callable[[AgentState, Action], PredResult]


def _destination(action: Action):
    """(display, host) for an outbound action: email 'to', web 'url', or
    payment 'iban'/'recipient'. Lets one set of checks cover all suites."""
    for key in ("to", "url", "iban", "recipient"):
        if key in action.args:
            val = str(action.args[key])
            if key == "url":
                host = re.sub(r"^https?://", "", val).split("/")[0]
            elif key == "to":
                host = val.split("@")[-1] if "@" in val else val
            else:
                host = val
            return val, host
    return "", ""


def _is_external(state: AgentState, display: str, host: str) -> bool:
    approved = {r.lower() for r in state.approved_recipients}
    return not (display.lower() in approved or host.lower() in approved)


def recipient_approved() -> Predicate:
    def f(state, action):
        display, host = _destination(action)
        ok = not _is_external(state, display, host)
        return PredResult(ok, f"recipient {display!r} {'is' if ok else 'is NOT'} on the allow-list", True)
    return f


def no_private_to_external() -> Predicate:
    """Structural exfiltration check: PRIVATE-tainted data -> external destination."""
    def f(state, action):
        display, host = _destination(action)
        external = _is_external(state, display, host)
        private = DataLabel.PRIVATE in action.tainted_labels
        violated = external and private
        reason = (f"PRIVATE-tainted data flowing to external destination {display!r}"
                  if violated else "no private->external dataflow")
        return PredResult(not violated, reason, True)
    return f


def approval_trusted() -> Predicate:
    """Proceed only if user-confirmed AND the approval's provenance is a real
    user turn (not injected content)."""
    def f(state, action):
        confirmed = action.kind in state.confirmed_kinds
        src = action.claims.get("approval")
        ok = confirmed and src == Source.USER_TURN
        if src == Source.INJECTED_DOC:
            reason = "approval claim originates from injected/untrusted content"
        elif not confirmed:
            reason = "no trusted user confirmation on record for this action"
        else:
            reason = "approval is user-confirmed and provenance-trusted"
        return PredResult(ok, reason, True)
    return f


_DESTRUCTIVE = re.compile(
    r"\brm\s+-[a-z]*r|\bmkfs\b|:\(\)\s*\{|\bdd\s+if=|>\s*/dev/sd|"
    r"chmod\s+-R\s+777|\bshutdown\b|drop\s+table", re.I)


def shell_not_destructive() -> Predicate:
    def f(state, action):
        cmd = str(action.args.get("command", ""))
        bad = bool(_DESTRUCTIVE.search(cmd))
        return PredResult(not bad, f"shell command {'is destructive' if bad else 'looks safe'}: {cmd!r}", True)
    return f


# --------------------------------------------------------------------------- #
# Policy DSL  (deny-overrides aggregation)
# --------------------------------------------------------------------------- #
class Verdict(str, Enum):
    ALLOW = "ALLOW"
    ASK_USER = "ASK_USER"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


_SEVERITY = {Verdict.ALLOW: 0, Verdict.ASK_USER: 1, Verdict.REVIEW: 2, Verdict.BLOCK: 3}


@dataclass
class Decision:
    verdict: Verdict
    reasons: list = field(default_factory=list)

    def __str__(self):
        r = "; ".join(self.reasons)
        return self.verdict.value + (f"  ({r})" if r else "")


@dataclass
class Rule:
    name: str
    kinds: tuple                       # action kinds, or ("*",) for all
    requires: list                     # list[Predicate]
    on_violation: Verdict = Verdict.BLOCK
    on_abstain: Verdict = Verdict.REVIEW

    def applies(self, action: Action) -> bool:
        return "*" in self.kinds or action.kind in self.kinds


@dataclass
class Policy:
    name: str
    rules: list

    def evaluate(self, state: AgentState, action: Action) -> Decision:
        worst = Verdict.ALLOW
        reasons: list = []
        for rule in self.rules:
            if not rule.applies(action):
                continue
            for pred in rule.requires:
                res = pred(state, action)
                if res.ok is True:
                    continue
                outcome = rule.on_violation if res.ok is False else rule.on_abstain
                tag = "VIOLATION" if res.ok is False else "ABSTAIN"
                reasons.append(f"[{rule.name}] {tag}: {res.reason}")
                if _SEVERITY[outcome] > _SEVERITY[worst]:
                    worst = outcome
        if not reasons:
            reasons.append("all policy requirements satisfied")
        return Decision(worst, reasons)


def default_policy() -> Policy:
    return Policy("default-agent-safety", [
        Rule("no-exfiltration", ("send_email", "web_request", "forward_email"), [no_private_to_external()]),
        Rule("email-recipient-allowlist", ("send_email", "forward_email"), [recipient_approved()], on_violation=Verdict.ASK_USER),
        Rule("require-trusted-approval", ("send_email", "forward_email"), [approval_trusted()], on_violation=Verdict.ASK_USER),
        Rule("no-destructive-shell", ("run_shell",), [shell_not_destructive()]),
        Rule("no-unapproved-payment", ("send_money", "transfer"), [recipient_approved(), approval_trusted()]),
        # destination backstop for link/web egress: an external destination is
        # flagged even when taint has been laundered away (closes the web-sink hole
        # the optimizing attacker found -- email already had this via the allow-list).
        Rule("no-untrusted-destination", ("open_link", "web_request"), [recipient_approved()], on_violation=Verdict.REVIEW),
        # consequential/irreversible non-egress actions require trusted user approval
        Rule("sensitive-action-needs-approval",
             ("delete", "update_credential", "modify_payment", "reserve", "access_change", "calendar_create"),
             [approval_trusted()], on_violation=Verdict.BLOCK),
    ])
