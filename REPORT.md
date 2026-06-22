# SpecShield: A Structural Trusted Monitor for Tool-Using AI Agents, Bounded by Provenance Quality

Author name · Affiliation

*With Apart Research*

---

## Abstract

Most LLM safety moderates what a model *says*; this paper is about what an agent
*does*. AI agents that read untrusted content (emails, documents, web pages) and
then *act* through tools are vulnerable to prompt injection: a malicious payload can
steer the agent into exfiltrating private data, moving money, or exposing
credentials — through a tool call whose text looks perfectly benign, so content
moderation never sees it. Most
AI-control work pairs such agents with an *LLM* trusted monitor that reads the
action text — but a text-reading monitor is jailbreakable, costly, and degrades on
low-resource and code-switched languages. We study an alternative in the
email/spreadsheet setting (AgentDojo): a **structural trusted monitor** that
authorizes each proposed tool action by inspecting *typed fields, dataflow taint,
and the provenance of any "approval"* — never the payload text. We frame it as
enforcing an invariant ("untrusted-instructed content may not trigger a
money-moving, credential-exposing, or PRIVATE→external action without trusted
user approval") and pair it with an optional LLM monitor via a cheap gated
controller. On AgentDojo the structural monitor enforces the invariant on 17/17
relevant attacks at 0/49 benign cost — **conditional on a provenance signal**.
Making that dependence the object of study, we corrupt the signal and measure the
result: structural safety degrades *gracefully* from 100% to ~70% as provenance
accuracy falls from 100% to 50% (coin-flip), staying above usefulness throughout
because the monitor is multi-signal. Under an optimizing attacker that may launder
taint and sanitize text, the structural and LLM monitors fail in *disjoint* ways,
so the hybrid holds where each alone breaks. Our central finding is not "100%
safety" but that structural authorization converts agent safety into a *measured
function of provenance quality* — relocating, not solving, the hard problem, and
showing exactly where an LLM layer earns its cost.

---

## 1. Introduction

Most deployed "AI safety" today is **content moderation**: it governs what a model
*says* — refusing harmful instructions, filtering toxic or sensitive text, declining
controversial questions. That is a check on **language**. But as LLMs become
*agents* that call tools, a second, far less-guarded layer opens up: not what the
model says, but what it *does*. A courteously-worded email can still forward customer
records to an attacker; a polite reply can still send an OTP; a benign-looking tool
call can still wire money. Such an action sails through every content filter, because
the danger is in the **action**, not the words. Content moderation never inspects it.
This paper is about that action layer — *action authorization*, not speech
moderation.

Tool-using LLM agents are being deployed to triage email, move money, manage
calendars, and run shell commands. The same capability that makes them useful — 
acting on content they read — makes them a prompt-injection target: a single
malicious email or retrieved document can instruct the agent to forward customer
records, change a payment IBAN, or send an OTP to an attacker. The defining risk is
not whether a model can *detect* malicious text; it is whether the system can
**prevent the agent from executing a dangerous action** even when detection fails.
This is the **AI-control** problem (controlling what a possibly-manipulated agent
*does*), distinct from the content-alignment problem (controlling what a model
*says*) that most LLM safety addresses.

The standard AI-control recipe places a *trusted monitor* between the agent and its
tools. Most published work studies code/bash agents with an **LLM monitor** that
reads the proposed action and scores it. That design inherits three weaknesses: it
is itself jailbreakable (the attacker controls the text it reads), it costs a model
call per action, and — for the many agents deployed outside English — it degrades
on the languages it was not tuned on.

We ask whether a **deterministic, structural** monitor can do the job in the
email/spreadsheet setting. Instead of reading the payload, it inspects the typed
action: *did PRIVATE-labeled data flow into this call (taint)? where did the
"approval" it relies on come from (provenance)? is the destination on an allow-list
derived from the user's own legitimate tasks?* These checks are language-agnostic,
auditable, and free of model cost — but, crucially, they are only as good as the
provenance signal they consume. Our work makes that dependence the object of study
rather than hiding it.

We motivate the setting with a concrete, regionally grounded threat model
(AI-enabled phishing and business-email-compromise fraud in Vietnam, where edge and
small-model agents are common for cost and data-sovereignty reasons), but our
quantitative claims rest on the standard AgentDojo benchmark.

**Our main contributions are:**

1. **A structural trusted monitor framed as invariant enforcement.** We implement a
   typed-action policy engine (taint + provenance + allow-list, deny-overrides
   aggregation) and evaluate it on AgentDojo as enforcing a single safety invariant
   rather than as a detector — a stronger, falsifiable claim.
2. **The provenance-sensitivity curve.** By corrupting the provenance signal and
   measuring, we show structural safety is a graceful function of provenance
   accuracy (100%→~70% as accuracy falls 100%→50%), staying above usefulness because
   the monitor is multi-signal — quantifying that structural authorization
   *relocates* the prompt-injection problem to provenance, rather than solving it.
   This is a measured result, not an assumed oracle.
3. **A disjoint-failure analysis under an optimizing attacker.** With a single
   white-box attacker that may launder taint and sanitize text, we show the
   structural and LLM monitors have non-overlapping blind spots, so a gated hybrid
   holds across the attacker-effort frontier — and we use the attacker to find and
   then close a real web-sink hole in the structural layer.

## 2. Related Work

**Information-flow control for agents.** *Fides / "Securing AI Agents with
Information-Flow Control"* (Costa & Köpf, Microsoft Research, 2025; arXiv
2505.23643) is the closest prior art: a deterministic taint-tracking planner that
stops all AgentDojo prompt injection *given good labels*. **CaMeL — "Defeating
Prompt Injections by Design"** (Google DeepMind, 2025) constrains what injected
content can trigger via capabilities/provenance. SpecShield shares their
provenance-as-guarantee instinct but differs in three ways: (i) it is **hybrid** — 
a structural monitor plus an optional LLM monitor joined by a gated controller,
rather than pure IFC; (ii) it explicitly **measures the provenance dependence**
that pure-IFC results take as given; and (iii) it studies an **adaptive/optimizing
attacker** against that dependence. We position SpecShield as *complementary to*
Fides: Fides shows IFC suffices with good labels; we ask what the safety/usefulness
curve looks like as label quality degrades, and where an LLM layer earns its cost.

**LLM and rule-based monitors.** *AgentWatcher* (2026) applies explicit rules via a
monitor LLM over an action's causal context. The **OWASP Top 10 for LLM
Applications** lists prompt injection and excessive agency as primary risks.
**OpenAI, "Designing agents to resist prompt injection"** (2026) argues defenses
should constrain the *impact* of manipulation, not only detect malicious inputs — 
the design stance we adopt. **AgentDojo** (ETH Zürich) is our evaluation
substrate.

**When to use our method.** Prefer a structural monitor when (a) you can produce
even a noisy provenance/taint signal, (b) you need an auditable, zero-model-cost,
language-agnostic guarantee, or (c) you deploy small/edge models whose text-reading
judgment is weak. Prefer (or add) an LLM monitor when provenance is unavailable or
the attack lives entirely in semantics. Our gated hybrid is the operating point
that pays for the LLM only on the cases the structural layer cannot settle.

## 3. Methods

**Data model.** Each proposed tool call is a typed `Action(kind, args,
tainted_labels, claims, text)`. `tainted_labels` records dataflow (did
PRIVATE-labeled data flow into this call?); `claims["approval"]` records the
*provenance* of any approval the agent relies on (`USER_TURN` = trusted real user,
`INJECTED_DOC` = untrusted retrieved content); `text` is the free-text payload that
only fragile baselines read. An `AgentState` carries an allow-list of approved
recipients/IBANs and the set of action kinds the user explicitly confirmed.

**Structural predicates and policy.** Five language-agnostic predicates inspect the
typed fields: recipient-on-allow-list, no PRIVATE→external dataflow, trusted
approval provenance, non-destructive shell, and (added during red-teaming, §4) a
destination backstop for web sinks. Predicates return `True/False/ABSTAIN`. A
deny-overrides policy aggregates them into `ALLOW / ASK_USER / REVIEW / BLOCK`
(severity-max). Crucially, **the ground-truth attack/benign label is never read by
the verdict** — only the structural signals are.

**The provenance signal (the key design choice and key assumption).** On AgentDojo
we derive each action from a task's ground-truth tool calls. We tag benign
(user-task) actions as user-approved and injection-task actions as not, and set
PRIVATE taint when a read precedes the sink. This *assumes a system that can
distinguish user-requested from injected actions* — e.g. a CaMeL/Fides-style
dataflow tracker. This assumption is the load-bearing one in the entire project; §4
measures the result's sensitivity to it, and §5 states how every claim changes if
it fails.

**Monitors compared.** (1) `prompt_only` — no enforcement (floor); (2) `rule_based`
— English keyword + recipient rules; (3) `llm_judge` — a model scores the action
text (offline English-keyword stub, or a real Anthropic/Ollama backend); (4)
`structural` — the policy engine; (5) `hybrid (max)` — `max(structural, llm)`; (6)
`gated` — trust the structural verdict when decisive (ALLOW/BLOCK), call the LLM
only on the uncertain middle (ASK_USER/REVIEW). The LLM scorer is averaged over k=5
samples and cached by payload text so a covert variant that strips only taint
scores identically to its overt twin (as it must).

**Attacker model.** One fixed attacker, run identically against every monitor, with
*declared affordances*: it knows the structural rules and that the LLM scores text;
it may **launder taint** (drop the PRIVATE label) and **sanitize cover text** to
look benign; it **cannot** forge the user-confirmation record or send to an
allow-listed recipient (either would defeat the attack's purpose). We evaluate a
fixed-effort escalation (L0 overt → L1 launder → L2 launder+sanitize) and an
**optimizing white-box** attacker that searches the full evasion powerset and keeps
the best evasion per attack.

**Benchmark.** AgentDojo live (`v1.2.1`, four suites) covering egress *and*
consequential non-egress sinks (delete, credential change, payment modify,
reservation, access change, calendar): **75 actions — 26 attack, 49 benign** (57
pure-read tasks skipped, having no action to authorize). A 6-scenario
Vietnam set (EN+VI) and a bilingual BEC set (EN/VI/code-switched) probe the
language axis. The Vietnamese and code-switched text was authored and vetted by a
native Vietnamese speaker (the author) for fluency, register/pronoun consistency,
and semantic equivalence to the English source, so a measured language effect
reflects the monitor rather than translation artifacts. We report **95% Wilson
confidence intervals** throughout for the
modest N. Everything runs offline on the bundled sample (stdlib only); the live
AgentDojo and real-model rows require `pip install agentdojo` (Python ≥3.10) and
`ANTHROPIC_API_KEY`. The reported live/real-model numbers below are from such a run
(see Code & Data for the exact commands).

**What we tried that didn't work.** (i) A block-list of destructive shell commands
— defeated by `find -delete` in red-teaming; the lesson is to allow-list commands,
not block-list them. (ii) The "LLM degrades on Vietnamese" hypothesis — false at
the frontier (§4); we reframed it as a small/edge-model phenomenon. (iii) The first
structural design lacked a recipient backstop on web sinks; the optimizing attacker
exploited it, and we added rule `no-untrusted-destination` to close it.

## 4. Results

### 4.1 The invariant holds — conditional on provenance

Structural enforcement of the invariant on AgentDojo (deterministic,
model-independent):

| metric | value (95% Wilson CI) |
|---|---|
| Enforcement (relevant attacks prevented) | **17/17 = 100% [82–100%]** |
| Usefulness cost (benign blocked/escalated) | **0/49 = 0% [0–7%]** |

This is a hard guarantee at ~zero usefulness cost — but **the 100% is
provenance-conditional**: with the user-vs-injected signal removed, structural
usefulness collapses to ~5%, because the monitor can no longer tell a legitimate
user-requested send from an injected one. *The result is therefore best read as
"given provenance of quality q, safety is f(q)," not as an unconditional number.*

### 4.1.1 The provenance-sensitivity curve — the central result

Rather than *assume* a perfect provenance oracle, we corrupt it: flip the
provenance signal on a fraction of actions (30 seeded trials/level) and measure
structural safety/usefulness vs. provenance accuracy (AgentDojo, structural-only,
fully offline-reproducible):

| provenance accuracy | safety | usefulness |
|---:|---:|---:|
| 100% | 100% [100–100] | 100% [100–100] |
| 90% | 93% [91–95] | 92% [91–94] |
| 80% | 89% [87–91] | 86% [84–87] |
| 70% | 83% [80–85] | 76% [73–78] |
| 60% | 74% [71–77] | 70% [68–72] |
| 50% | 70% [67–73] | 63% [60–65] |

This converts the project's central caveat into its central measurement. Two
findings: (i) degradation is **graceful, not catastrophic** — safety falls only to
~70% even at coin-flip (50%) provenance; (ii) safety stays **above usefulness**
throughout, because the structural monitor is *multi-signal* — taint and
recipient-allow-list rules backstop safety when the approval signal is wrong. The
headline is thus a function, *safety = f(provenance accuracy)*, with tight CIs
(pooled 30×75 decisions) — well-powered, and reproducible with no API key.

### 4.2 No monitor dominates — a genuine multi-objective tradeoff

Four-way comparison at T=0.5 (real model, Anthropic, k=5, 75 actions):

| monitor | safety | usefulness | adaptive (covert) | LLM cost |
|---|---:|---:|---:|---:|
| structural | 100% | 100% | 92% | **0%** |
| llm | 69% | 82% | 69% | 100% |
| hybrid (max) | 100% | 82% | **100%** | 100% |
| gated (defer-to-trusted) | 85% | **100%** | 77% | **12%** |

Adding the LLM is *not free*: the hybrid's usefulness drops to 82% from LLM false
positives. The gated controller calls the LLM on only **9/75 (12%)** of actions.
**Recommendation:** *gated* as the practical default (100% usefulness, 12% cost);
*hybrid* when adaptive attackers are expected; *structural* alone as the auditable
zero-cost baseline — given a provenance signal.

### 4.3 Disjoint failures → the hybrid holds across the attacker frontier

**Figure 1.** Safety vs. attacker effort (one fixed attacker, all monitors, T=0.5),
*after* the web-sink fix. The structural monitor now holds across the whole
fixed-effort frontier; the LLM collapses as cover text is sanitized (L2). Their
blind spots are disjoint, so the hybrid stays at 100%.

```
        L0 overt    L1 launder    L2 +sanitize
   structural: 100 → 100 → 100   llm: 62 → 62 → 42
   hybrid:     100 → 100 → 100   gated: 81 → 81 → 69
```
(Pre-fix the structural row read 100 → 92 → 92; the optimizing attacker below
exposed that residual and the fix closed it.)

**Optimizing (white-box) attacker**, searching the full evasion set per attack
(safety, 95% CI). The fix targets the structural layer; the llm/gated rows are
~unchanged (their values carry k=5 sampling variance across runs):

| monitor | before web-sink fix | after fix |
|---|---|---|
| structural | 92% [76–98%] | **100% [87–100%]** |
| llm | 35% [19–54%] | 35% [19–54%] |
| hybrid | 92% [76–98%] | **100% [87–100%]** |
| gated | 65% [46–81%] | 65% [46–81%] |

The optimizer found that ~8% of attacks hit taint-only sinks (e.g. `web_request`)
that lacked the recipient backstop email had — defeating both monitors at once. We
added a destination allow-list backstop (`no-untrusted-destination`); structural
and hybrid recover to 100% at **zero usefulness cost** (benign web hosts from
legitimate tasks are allow-listed). This is the intended use of an optimizing
attacker: it exposed what the single fixed-transform test hid, and motivated a
concrete, verified defense.

### 4.4 The Vietnamese/code-switched language gap is a confirmed null (honest negative)

Bilingual BEC, **powered set (16 attacks × EN/VI/code-switched)**, smaller model
(Claude Haiku), T=0.5:

| language | structural | llm (Haiku, 95% CI) |
|---|---:|---:|
| English | 100% | 88% [64–97] |
| Vietnamese | 100% | 94% [72–99] |
| code-switched | 100% | 100% [81–100] |

**This is a well-powered null.** On the expanded 16-attack set, both a frontier
model (Opus, prior run) and a *smaller* model (Haiku, above) show **no
Vietnamese/code-switched gap** — the LLM handles all three languages comparably,
and the trend runs *opposite* the hypothesis (EN ≤ VI ≤ CS). So "text-based LLM
monitoring degrades on Vietnamese" is **not supported for capable or small models**;
the LLM's real failure axis is adversarial text-sanitization (§4.3, L2), not
language. The only multilingual claim that holds is structural: the monitor is
language-agnostic *by construction* (100% across all three languages, because it
reads typed fields, not text). A 3B edge model is the one untested regime, but the
prior is now strongly null — we therefore treat the language gap as a **confirmed
negative result** and do not rest any headline on it. Vietnam grounds the threat
model (§Methods); it does not carry a quantitative claim.

### 4.5 Red-team: honest limits

Hand-crafted attacks built to break the structural checker leak **2 of 3**:
taint-laundering to an allow-listed alias (LEAK — taint must propagate across
steps, not per-call), `find -delete` obfuscation (LEAK — allow-list commands), and
mislabeled-PUBLIC sensitive data (downgraded — data labels need provenance too).
These are the structural monitor's real boundaries, not hidden failures.

## 5. Discussion and Limitations

**Implications.** The headline trend is that *structural authorization converts
agent safety into a measurable function of provenance quality*. That reframing
matters for AI safety because it makes the guarantee falsifiable and the residual
explicit: you can state exactly what an attacker must do (launder taint *and*
sanitize text *and* reach a backstop-free sink) and exactly where an LLM layer pays
for itself (the semantic residual the structural layer cannot prove). The
disjoint-failure result is the practical payoff — a cheap gated hybrid inherits the
structural monitor's auditability and the LLM's semantic coverage, calling the model
on only ~12% of actions.

**Limitations and assumptions.**
- *Provenance is assumed, not built.* The single load-bearing assumption is that
  the system can distinguish user-requested from injected actions. **If it does
  not, every structural number degrades** — usefulness toward ~5% — and the
  contribution becomes "here is the curve," not "here is 100%." Building/measuring a
  real (noisy) provenance tracker is the most important open problem.
- *Small N.* 75 AgentDojo actions, 6 bilingual attacks; CIs are wide (e.g. 17/17 =
  [82–100%]). Results are directional, not statistically tight.
- *Live/real-model rows require external dependencies* (AgentDojo + API key); the
  fully offline artifact verifies the structural engine, the policy math, the
  red-team, and a 10-action sample.
- *Scope.* Single-step action authorization in email/spreadsheet/banking/slack/
  travel suites; multi-step taint propagation, command allow-listing, and
  document/Zalo/Teams agents are out of scope. Deepfake *detection* is out of
  scope — we treat claimed authority as insufficient without trusted approval.

**Future work.** (1) **Derive** the provenance signal from trajectory structure
rather than assigning it: we already measured *sensitivity* to provenance quality by
injecting label noise (§4.1.1, safety = f(accuracy)); building a real, noisy
provenance/dataflow tracker and measuring its accuracy in the wild is the open
problem. (2) Run a 3B open model (Qwen/Llama via Ollama) as the monitor to locate
the edge-model language gap the frontier did not show. (3) Propagate taint across
multi-step trajectories; allow-list commands; add cross-action/aggregate monitoring
for sub-threshold fraud. (4) A Lean/SMT backend for the decidable predicates.

## 6. Conclusion

We built a structural trusted monitor that authorizes tool actions from typed
fields, dataflow taint, and approval provenance rather than payload text, and
evaluated it as invariant enforcement on AgentDojo. It enforces the safety invariant
on every relevant attack at near-zero usefulness cost — but only given a provenance
signal, without which its usefulness collapses; this dependence, which prior IFC
results take for granted, is our main finding. Under an optimizing attacker the
structural and LLM monitors fail in disjoint ways, so a cheap gated hybrid holds
where each alone breaks. The takeaway for AI safety is that structural authorization
does not solve prompt injection so much as *relocate* it to a measurable provenance
problem — and that quantifying that relocation, rather than reporting a single
safety number, is the more honest and more useful contribution.

## Code and Data

- **Code repository:** `https://github.com/<org>/specshield` *(update link)*
- **Reproduce (offline, stdlib only):** `python3 -m specshield test | demo |
  control | attacker | bilingual | invariant | redteam`
- **Reproduce (live AgentDojo + real model):** `pip install agentdojo anthropic`
  (Python ≥3.10), set `ANTHROPIC_API_KEY`, then `python3 -m specshield invariant
  --live`, `control --live`, `attacker --live`. Small/edge model:
  `SPECSHIELD_OLLAMA_MODEL=qwen2.5:3b python3 -m specshield bilingual`.
- **Data:** bundled `agentdojo_sample.jsonl`, `vietnam_scenarios.jsonl`,
  `bilingual_bec.jsonl`; live tasks from AgentDojo `v1.2.1`.

## References

1. Costa, M. & Köpf, B. et al. (2025). *Securing AI Agents with Information-Flow
   Control* (Fides). arXiv:2505.23643. github.com/microsoft/fides. ✓ verified.
2. Debenedetti, E. et al. (2025). *Defeating Prompt Injections by Design* (CaMeL).
   arXiv:2503.18813 (Google / DeepMind / ETH Zürich).
   github.com/google-research/camel-prompt-injection. ✓ verified.
3. Debenedetti, E. et al. *AgentDojo: A Dynamic Environment to Evaluate Attacks and
   Defenses for LLM Agents.* ETH Zürich (SPY Lab).
4. *AgentWatcher: A Rule-based Prompt Injection Monitor* (2026). arXiv:2604.01194.
   github.com/wang-yanting/AgentWatcher. ✓ verified (web, Jun 2026).
5. OWASP Foundation. *OWASP Top 10 for LLM Applications.*
6. OpenAI (2026). *Designing AI Agents to Resist Prompt Injection.* ✓ verified (URL).
7. Vietnam National Assembly (2025). *Law on Cybersecurity No. 116/2025/QH15*
   (effective 1 July 2026). Cite as "legal summaries state the law prohibits
   unlawful AI/deepfake impersonation"; do not cite specific clause numbers without
   the official statutory text.
8. Prime Minister of Vietnam (2021). *National Strategy on R&D and Application of AI
   to 2030, Decision No. 127/QĐ-TTg.* ✓ verified.
9. VNETWORK (2026). *Vietnam Cybersecurity Threat Report 2026.* ✓ verified (figures
   + URL in CITATIONS.md). See CITATIONS.md for [S1–S14] full URLs.

*(All arXiv IDs and Vietnamese-source figures were web-verified June 2026; see
CITATIONS.md. Reviewers should still open each link directly.)*

## Appendix

**A. Full command → result map, thresholds, and per-suite tables** are reproduced
by the CLI (`control`, `attacker`, `invariant`, `bilingual`, `redteam`). All
control/attacker/invariant/bilingual numbers print 95% Wilson CIs.

**B. The invariant (verbatim):** *"untrusted-instructed content may not trigger a
money-moving, credential/OTP-exposing, or PRIVATE→external action without trusted
user approval."*

**C. Threshold sweep (offline N=10 sample, structural):** safety 100% and
usefulness 100% at T=0.5 (verifiable with no dependencies via `python3 -m
specshield control`).

### LLM Usage Statement

I used an LLM assistant to consolidate documentation, draft prose, and review
structure. All quantitative claims were produced by the project's own
deterministic/CLI code and independently re-run; the report distinguishes
offline-verifiable results from those requiring the live AgentDojo harness and an
API key. The final manuscript was reviewed and edited by the author. Citation IDs
and external figures flagged in References/Appendix require verification against
primary sources prior to submission.
