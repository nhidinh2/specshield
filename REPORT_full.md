# SpecShield: A Structural Trusted Monitor for Tool-Using AI Agents, Bounded by Provenance Quality

Author name · Affiliation

*With Apart Research*

---

## Abstract

Most LLM safety moderates what a model *says*; this paper is about what an agent
*does*. Tool-using agents that act on untrusted content are vulnerable to prompt
injection — a tool call whose text looks benign can still exfiltrate data or move
money, so content moderation never sees it. We study a **structural trusted monitor**
on AgentDojo that authorizes each action from typed fields, dataflow taint, and the
provenance of any approval — never the payload text — framed as enforcing a safety
invariant. It catches every relevant attack at near-zero usefulness cost, but
**conditional on a provenance signal**. Making that dependence the object of study,
we corrupt the signal and measure: on the representative 75-action set, structural
safety **degrades gracefully from 100% to ~70% as provenance accuracy falls to a
coin-flip**, never collapsing, because the monitor is multi-signal (100% when every
attack also trips a taint/recipient rule). Under an optimizing attacker that may
launder taint and sanitize text, the structural and LLM monitors fail in *disjoint*
ways, so a cheap gated hybrid holds where each alone breaks. The contribution is not
"100% safety" but converting agent safety into a **measured function of provenance
quality** — relocating, not solving, prompt injection.

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

**Why email, and why now.** Email is the dominant attack surface: ~60% of breaches
involve the human element, phishing is a leading initial-access vector, and
business email compromise (BEC) is the costliest social-engineering category —
roughly **US$6.3B** in reported losses and **58%** of financially-motivated
phishing breaches (2025 Verizon DBIR [S16]). As Vietnamese firms race to adopt AI
assistants that *read mail and act on company systems*, they wire this highest-value
attack surface directly to tools that can move money and export data — turning the
assistant itself into the attack surface. SpecShield is a thin **authorization layer
between the assistant and its tools**, independent of the model, so it holds even
when the assistant is manipulated. We motivate the setting with a concrete,
regionally grounded threat model (AI-enabled phishing and BEC fraud in Vietnam,
where edge and small-model agents are common for cost and data-sovereignty reasons),
but our quantitative claims rest on the standard AgentDojo benchmark.

**Our main contributions are:**

1. **A structural trusted monitor framed as invariant enforcement.** We implement a
   typed-action policy engine (taint + provenance + allow-list, deny-overrides
   aggregation) and evaluate it on AgentDojo as enforcing a single safety invariant
   rather than as a detector — a stronger, falsifiable claim.
2. **The provenance-sensitivity curve.** By corrupting the provenance signal and
   measuring (not assuming an oracle), we quantify how safety depends on provenance
   quality, and show it is governed by *non-provenance backstops*: on the small
   sample (attacks also caught by taint/recipient) safety stays at 100% down to
   coin-flip and only usefulness pays (100%→~50%); on the 75-action set where ~30% of
   attacks rely on the approval signal alone, **safety degrades gracefully to ~70%**
   at coin-flip. This quantifies that structural authorization *relocates* the
   prompt-injection problem to provenance, with the cost split set by how many
   attacks have independent red flags.
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
the verdict** — only the structural signals are. The invariant the policy enforces,
verbatim: *"untrusted-instructed content may not trigger a money-moving,
credential/OTP-exposing, or PRIVATE→external action without trusted user approval."*

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

**Table 1.** Structural enforcement of the invariant on AgentDojo (deterministic,
model-independent): every relevant attack prevented at zero benign cost, *given*
the provenance signal.

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
structural safety/usefulness vs. provenance accuracy. We report **both** datasets,
because the difference between them *is* the finding.

**Table 2.** Structural safety/usefulness as the provenance signal is corrupted
(30 seeded trials/level, 95% Wilson CIs). Both rows reproduce with no API key:
`provnoise` (offline) and `provnoise --live` (75-action AgentDojo, py≥3.10).

| prov. accuracy | safety (offline, 6 atk) | usefulness | safety (live, 26 atk) | usefulness |
|---:|---:|---:|---:|---:|
| 100% | 100% | 100% | 100% | 100% |
| 90% | 100% | 91% | 93% | 92% |
| 80% | 100% | 77% | 89% | 86% |
| 70% | 100% | 62% | 83% | 76% |
| 60% | 100% | 56% | 74% | 70% |
| 50% | 100% | 51% | **70%** | 63% |

This converts the project's central caveat into its central measurement — and the
**gap between the two columns is the result**. Safety's robustness to provenance
noise is governed by *non-provenance backstops*: where every attack also trips a
taint or recipient rule (the offline sample), corrupting provenance only over-blocks
benign actions, so **safety stays 100% and the whole cost lands on usefulness**
(100%→~51%). On the larger, more representative live set, **~30% of attacks are
caught by the approval signal alone** (e.g. an internal-looking payment with no other
red flag); when provenance degrades, those slip, so **safety degrades gracefully to
~70% at coin-flip**. Neither collapses to zero — the multi-signal design *fails soft*.

The honest takeaway is therefore not "safety stays 100%" but: *structural safety is a
measured function of provenance quality, bounded below by how many attacks carry
independent red flags.* A reviewer running `provnoise --live` sees the 70% floor, and
we report it as primary; the offline 100% is the (real) best case when all attacks
are multiply-caught.

### 4.2 No monitor dominates — a genuine multi-objective tradeoff

**Table 3.** Four-way monitor comparison at T=0.5 (real model, Anthropic, k=5,
75 actions). No monitor dominates on all of safety / usefulness / adaptive
robustness / cost — the tradeoff is genuine.

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

**Table 4.** Optimizing (white-box) attacker, searching the full evasion set per
attack (safety, 95% CI). The fix targets the structural layer; the llm/gated rows
are ~unchanged (their values carry k=5 sampling variance across runs).

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

**Table 5.** Bilingual BEC, expanded set (16 attacks × EN/VI/code-switched),
smaller model (Claude Haiku), T=0.5. No Vietnamese/code-switched gap — a
well-powered null.

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

**Where SpecShield sits: three layers of agent defense.** A deployed AI assistant
needs defense in depth, and the layers answer different questions: (1) **content
moderation** governs *what the model says* (refusals, toxicity filters); (2)
**SpecShield / content-provenance** governs *what an injected document can make a
trusted-user agent do* — the layer this paper studies; (3) **authority separation**
(least privilege, segregation of duties, aggregate monitoring) governs *what even a
malicious user or compromised operator can make the agent do*. The layers are
orthogonal: content moderation does not inspect actions, SpecShield trusts the user,
and authority separation does not read content. SpecShield is the missing middle for
the email/workflow assistants Vietnamese firms are now deploying — necessary, but to
be composed with (1) and (3), not a standalone shield.

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
- *Malicious operator (the trust-anchor limit).* SpecShield trusts the **user** as
  the authorization anchor: its invariant is "untrusted *content* may not act without
  trusted *user* approval." It therefore does **not** defend against a malicious or
  compromised operator who drives the agent directly — the threat realized in the
  Nov-2025 AI-orchestrated espionage campaign, where the human operator decomposed an
  attack into innocent-looking subtasks for an agent with broad system access [S15].
  Defending that case needs a different, *complementary* invariant — **authority
  separation**: least-privilege tool scoping so the agent never holds company-wide
  access, **segregation of duties** (high-impact actions require a second, independent
  approver, so no single principal can unilaterally trigger them), out-of-band step-up
  auth for irreversible actions, and **aggregate/cross-action monitoring** (rate,
  volume, fan-out) to catch sub-threshold decompositions that no per-action check
  sees. SpecShield's content-provenance invariant and this authority-separation
  invariant are orthogonal layers; we enforce the former, not the latter.

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

## Author Contributions

Sole author: designed the structural policy engine, attacker and provenance-noise
harnesses, and the AgentDojo adapter; authored and vetted the Vietnamese/code-
switched scenarios as a native speaker; ran all experiments and wrote the report.

## References

All arXiv IDs, URLs, and Vietnamese-source figures were web-verified June 2026.
Bracketed `[S#]` tags are used in the text.

**Prior work / methods.**

1. [S8] Costa, M. & Köpf, B. et al. (2025). *Securing AI Agents with Information-Flow
   Control* (Fides). arXiv:2505.23643. https://arxiv.org/abs/2505.23643 ·
   https://github.com/microsoft/fides
2. [S11] Debenedetti, E. et al. (2025). *Defeating Prompt Injections by Design*
   (CaMeL). arXiv:2503.18813. https://arxiv.org/abs/2503.18813 ·
   https://github.com/google-research/camel-prompt-injection
3. Debenedetti, E. et al. (2024). *AgentDojo: A Dynamic Environment to Evaluate
   Attacks and Defenses for LLM Agents.* arXiv:2406.13352.
   https://arxiv.org/abs/2406.13352 · https://github.com/ethz-spylab/agentdojo
4. [S9] *AgentWatcher: A Rule-based Prompt Injection Monitor* (2026). arXiv:2604.01194.
   https://arxiv.org/abs/2604.01194 · https://github.com/wang-yanting/AgentWatcher
5. [S7] OWASP Foundation. *OWASP Top 10 for LLM Applications.*
   https://genai.owasp.org/llm-top-10/
6. [S10] OpenAI (2026). *Designing AI Agents to Resist Prompt Injection.*
   https://openai.com/index/designing-agents-to-resist-prompt-injection/
7. [S16] Verizon (2025). *2025 Data Breach Investigations Report (DBIR).*
   https://www.verizon.com/business/resources/reports/dbir/
8. [S15] Anthropic (2025). *Disrupting the first reported AI-orchestrated cyber
   espionage campaign.* https://www.anthropic.com/news/disrupting-AI-espionage

**Vietnam threat-model grounding.**

9. [S12] Authority of Information Security (Bộ TT&TT) / VietnamPlus (2025). *Vietnam
   intensifies fight against deepfake-powered online scams.*
   https://en.vietnamplus.vn/vietnam-intensifies-fight-against-deepfake-powered-online-scams-post336945.vnp
10. [S13] RMIT University (Jun 2026). *AI-driven trade fraud raises alarm for
    Vietnamese exporters.*
    https://www.rmit.edu.vn/news/all-news/2026/jun/ai-driven-trade-fraud-raises-alarm-for-vietnamese-exporters
11. [S14] *Business Email Compromise statistics* (deepstrike.io) and *AI invoice fraud*
    (pathquest.com), 2026. https://deepstrike.io/blog/business-email-compromise-statistics ·
    https://pathquest.com/knowledge-center/blogs/ai-invoice-fraud-ap-automation-2026/
12. [S1] VNETWORK (2026). *Vietnam Cybersecurity Threat Report 2026.*
    https://www.vnetwork.vn/en-US/bao-cao-tan-cong-mang-viet-nam-2026/
13. [S2] VietnamNet (12 Jan 2026). *Deepfake scams expected to surge in 2026.*
    https://vietnamnet.vn/en/deepfake-scams-expected-to-surge-in-2026-cybersecurity-experts-warn-2480964.html
14. [S3] VnEconomy (23 Mar 2026). *Cyberattack damage far exceeds traditional crime
    losses.* https://en.vneconomy.vn/cyberattack-damage-far-exceeds-traditional-crime-losses.htm
15. [S4] Vietnam.vn / A05 (2025). *Nationwide Anti-Fraud media campaign.*
    https://www.vietnam.vn/en/cong-bo-chien-dich-truyen-thong-toan-dan-chong-lua-dao
16. [S5] Vietnam National Assembly (2025). *Law on Cybersecurity No. 116/2025/QH15*
    (effective 1 Jul 2026). Cite as "legal summaries state the law prohibits unlawful
    AI/deepfake impersonation"; do not cite clause numbers without the statutory text.
    https://english.luatvietnam.vn/lawoncybersecurityno116-2025-qh15dateddecember102025ofthenationalassembly-422396-doc1.html
17. [S6] Prime Minister of Vietnam (2021). *National Strategy on R&D and Application
    of AI to 2030, Decision No. 127/QĐ-TTg.*
    https://en.baochinhphu.vn/national-strategy-on-rd-and-application-of-artificial-intelligence-11140663.htm

## Appendix

**Threat-model coverage — scenarios are grounded, not invented.** Each Vietnam /
bilingual scenario maps to a *documented* recent attack type in Vietnam, traced to a
source (scope: only attacks where an email/office agent reads untrusted content and
then takes a tool action; person-targeted scams with no agent action are out of scope
by construction).

| scenario | documented attack type | source |
|---|---|---|
| `vn_deepfake_ceo` | deepfake / executive authority impersonation (#1, 2025) | [S12][S2] |
| `vn_bank_otp` / `otp_verify` | bank/police impersonation + OTP theft | [S12][S4] |
| `vn_malicious_link` | phishing link / smishing | [S12] |
| `vn_fake_invoice` / `wire_change` | AI BEC / vendor wire-change | [S13][S14] |
| `invoice_urgent` | AI invoice fraud / urgency | [S14] |
| `payroll_redirect` | payroll / payment diversion (BEC variant) | [S13] |
| `data_audit` | pretext data exfiltration (audit/consultant) | [S13] |
| `contract_forward` | executive impersonation + exfiltration | [S13][S2] |
| `vn_mixed_injection` | AI prompt injection, VN-EN code-switched | [S7] |

*Covered: 10/10 email-agent-relevant documented types.* **Honest gap:**
sub-threshold invoice splitting [S14] is an *aggregate* pattern (each payment below
the review threshold) that **no per-action monitor — structural or LLM — can catch by
design**; we do not count it as caught, and it motivates the future cross-action
monitoring in §5.

### LLM Usage Statement

I used an LLM assistant to consolidate documentation, draft prose, and review
structure. All quantitative claims were produced by the project's own
deterministic/CLI code and independently re-run; the report distinguishes
offline-verifiable results from those requiring the live AgentDojo harness and an
API key. The final manuscript was reviewed and edited by the author. Citation IDs
and external figures flagged in References/Appendix require verification against
primary sources prior to submission.
