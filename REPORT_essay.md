# SpecShield: A Structural Trusted Monitor for Tool-Using AI Agents, Bounded by Provenance Quality

Author name · Affiliation — *With Apart Research*

---

Almost everything we currently call "AI safety" is really content moderation. It
governs what a model *says*: it refuses harmful instructions, filters toxic or
sensitive text, and declines questions it judges out of bounds. That is a check on
language, and for a chatbot it is the whole game. But as language models stop being
chatbots and start being *agents* — systems that read email, move money, manage
calendars, and run shell commands — a second and far less guarded layer opens up.
The question is no longer only what the model says, but what it *does*. A
courteously worded email can still forward a customer database to a stranger; a
polite reply can still leak a one-time passcode; a perfectly benign-looking tool
call can still wire money to the wrong account. Each of those actions sails through
every content filter ever built, because the danger lives in the action, not the
words, and content moderation never inspects the action at all. This essay is about
that second layer — about *authorizing what an agent does* rather than moderating
what it says.

The reason the action layer matters now is that tool-using agents are being
deployed into exactly the workflows where a wrong action is expensive. The same
property that makes them useful — that they act on the content they read — is what
makes them a prompt-injection target. A single malicious email or retrieved
document can instruct an agent to change a payment IBAN, export records, or relay a
verification code, and the agent, having no way to distinguish a legitimate
instruction from a planted one, may simply comply. The defining risk is therefore
not whether a model can *detect* malicious text. It is whether the surrounding
system can *prevent a manipulated agent from executing a dangerous action even when
detection fails*. That is the AI-control problem — controlling what a
possibly-compromised agent does — and it is genuinely distinct from the
content-alignment problem of controlling what a model says.

The standard recipe for AI control places a trusted monitor between the agent and
its tools. Most published work studies code and shell agents guarded by an *LLM
monitor*: a second model reads the proposed action and scores how dangerous it
looks. That design is reasonable, but it inherits three weaknesses that are easy to
state and hard to escape. It is itself jailbreakable, because the attacker controls
the very text the monitor reads. It costs a model call on every single action. And,
for the very large fraction of agents deployed outside English, it degrades on the
languages it was never tuned on. SpecShield asks a different question: in the
email-and-spreadsheet setting — money, records, credentials, calendars — can a
*deterministic, structural* monitor do the job instead?

## What "structural" means

A structural monitor does not read the payload. Instead of asking "does this text
look malicious," it inspects the typed shape of the action and asks three concrete
questions. Did data labeled PRIVATE flow into this call — that is, is there *taint*?
Where did the approval the agent is relying on actually come from — what is its
*provenance*, a real user turn or an untrusted retrieved document? And is the
destination on an allow-list derived from the user's own legitimate tasks? These
checks are language-agnostic by construction, fully auditable, and free of any model
cost. The catch — and it is the whole story of this project — is that they are only
as good as the provenance signal they consume. Rather than hide that dependence, we
have tried to make it the object of study.

Concretely, each proposed tool call is modeled as a typed `Action` carrying its
kind, its arguments, the set of tainted labels that flowed into it, the claims it
relies on (including the provenance of any approval, tagged `USER_TURN` for a
trusted real user or `INJECTED_DOC` for untrusted retrieved content), and the
free-text payload that only the fragile baselines ever read. Alongside it, an
`AgentState` records the allow-list of approved recipients and account numbers and
the set of action kinds the user explicitly confirmed. Five language-agnostic
predicates inspect those typed fields — recipient-on-allow-list, no PRIVATE-to-
external dataflow, trusted approval provenance, non-destructive shell, and a
destination backstop for web sinks that we added during red-teaming. Each predicate
returns true, false, or abstain, and a deny-overrides policy aggregates them by
severity into one of four verdicts: allow, ask-the-user, send-for-review, or block.
The invariant the whole policy exists to enforce, stated verbatim, is this:
*untrusted-instructed content may not trigger a money-moving,
credential/OTP-exposing, or PRIVATE-to-external action without trusted user
approval.* Crucially, the ground-truth attack-or-benign label is never read by the
verdict; only the structural signals are.

That last point is also where the central assumption lives, so it is worth being
blunt about it. On AgentDojo, we derive each action from a task's ground-truth tool
calls: benign user-task actions are tagged user-approved, injection-task actions are
not, and PRIVATE taint is set when a read precedes a sink. This *assumes a system
that can already distinguish user-requested actions from injected ones* — exactly
the signal a CaMeL- or Fides-style dataflow tracker is built to produce. That
assumption is the single load-bearing beam of the entire project. We do not build
the tracker; we assume an oracle version of its output and then, rather than leaving
it at that, spend the core of the paper measuring what happens as the signal
degrades.

## How SpecShield relates to prior work

The closest prior art is *Fides* — Costa and Köpf's "Securing AI Agents with
Information-Flow Control" (Microsoft Research, 2025) — a deterministic
taint-tracking planner that stops all AgentDojo prompt injection given good labels,
and Google DeepMind's *CaMeL*, "Defeating Prompt Injections by Design," which
constrains what injected content can trigger via capabilities and provenance.
SpecShield shares their provenance-as-guarantee instinct but diverges in three
ways. It is hybrid rather than pure information-flow control: a structural monitor
plus an optional LLM monitor, joined by a gated controller. It explicitly *measures*
the provenance dependence that pure-IFC results take as given. And it studies an
*adaptive, optimizing* attacker against that dependence rather than a fixed one. The
honest framing is that SpecShield is complementary to Fides: Fides shows that
information-flow control suffices when labels are good; we ask what the
safety-versus-usefulness curve looks like as label quality falls, and where an LLM
layer earns its keep. The surrounding literature supports the design stance —
AgentWatcher (2026) applies explicit rules via a monitor LLM, the OWASP Top 10 for
LLM Applications lists prompt injection and excessive agency as primary risks, and
OpenAI's 2026 "Designing Agents to Resist Prompt Injection" argues that defenses
should constrain the *impact* of manipulation rather than only detect malicious
input, which is precisely the posture we adopt. AgentDojo (ETH Zürich) is our
evaluation substrate.

A short rule of thumb falls out of all this. Prefer a structural monitor when you
can produce even a noisy provenance signal, when you need an auditable, zero-cost,
language-agnostic guarantee, or when you deploy small edge models whose
text-reading judgment is weak. Prefer — or add — an LLM monitor when provenance is
simply unavailable or when the attack lives entirely in semantics. The gated hybrid,
which we return to below, is the operating point that pays for the LLM only on the
cases the structural layer cannot settle by itself.

## Why email, and why Vietnam

Email is the dominant attack surface in the real world: roughly 60% of breaches
involve the human element, phishing remains a leading initial-access vector, and
business email compromise is the costliest social-engineering category — on the
order of US$6.3 billion in reported losses and 58% of financially-motivated
phishing breaches, per the 2025 Verizon DBIR. As firms race to adopt assistants that
read mail and act on company systems, they wire this highest-value attack surface
directly to tools that can move money and export data, turning the assistant itself
into the attack surface. We motivate the work with a concrete, regionally grounded
threat model — AI-enabled phishing and BEC fraud in Vietnam, where edge and
small-model agents are common for cost and data-sovereignty reasons — but it is
important to be clear that Vietnam grounds the *threat model*, not the quantitative
claims. The numbers below rest on the standard AgentDojo benchmark; the Vietnamese
material exists to make the setting concrete and, as it turns out, to retire a
hypothesis we initially believed.

## The benchmark, and what we actually measured

We evaluate on live AgentDojo (v1.2.1, four suites) covering both egress sinks and
consequential non-egress sinks — deletion, credential change, payment modification,
reservations, access changes, calendar writes. After skipping the 57 pure-read
tasks that have no action to authorize, this leaves 75 actions: 26 attacks and 49
benign. A six-scenario Vietnam set and a bilingual BEC set, both authored and vetted
by a native Vietnamese speaker for fluency and semantic equivalence to the English
source, probe the language axis. Because the action counts are modest, we report 95%
Wilson confidence intervals throughout. The structural engine, the policy math, the
red-team, and a ten-action sample all run fully offline on bundled data with nothing
but the Python standard library; the live AgentDojo rows and the real-model rows
require installing AgentDojo and setting an API key, and the live and real-model
figures reported here come from such a run.

The first result is that the invariant holds — conditional on provenance. Run
deterministically and model-independently, the structural monitor prevents every
relevant attack (17 of 17, 95% CI 82–100%) at zero usefulness cost (0 of 49 benign
actions blocked or escalated). That is a hard guarantee at essentially no cost. But
the word *conditional* is load-bearing: remove the user-versus-injected signal
entirely and structural usefulness collapses to roughly 5%, because the monitor can
no longer tell a legitimate user-requested send from an injected one and starts
refusing everything. The right way to read the headline is therefore not "100%
safe" but "given provenance of quality q, safety is some function f(q)."

## The central result: a provenance-sensitivity curve

So rather than assume a perfect provenance oracle, we corrupt it. We flip the
provenance signal on a controlled fraction of actions, run thirty seeded trials per
noise level, and watch structural safety and usefulness as a function of provenance
accuracy — and we report two datasets side by side, because the *difference between
them is the finding*.

On the offline six-attack sample, safety stays pinned at 100% all the way down to
coin-flip provenance accuracy, while usefulness slides from 100% to about 51%. On
the larger, more representative live set of 26 attacks, safety degrades — but
gracefully, from 100% at perfect provenance to roughly 70% at coin-flip, with
usefulness falling from 100% to about 63% over the same range. Neither column ever
collapses to zero. The mechanism behind the gap is the whole point. Where every
attack also trips an independent taint or recipient rule — as happens to be true of
the small offline sample — corrupting provenance can only ever over-block benign
actions, so the entire cost lands on usefulness and safety is untouched. On the
representative live set, about 30% of attacks rely on the approval signal *alone* —
think of an internal-looking payment that carries no other red flag — and when
provenance degrades, exactly those attacks slip through. The multi-signal design
fails soft rather than failing open.

The honest takeaway, then, is not "safety stays 100%." It is that structural safety
is a *measured function of provenance quality, bounded below by how many attacks
carry independent red flags*. A reviewer who runs the live harness sees the 70%
floor, and we report it as the primary number; the offline 100% is a real but
best-case figure that holds only when every attack is multiply-caught.

## No monitor dominates

The second result is that, once you compare monitors honestly, none of them wins on
every axis — the tradeoff is genuine. Evaluated at temperature 0.5 against a real
Anthropic model, averaged over five samples, on all 75 actions, four monitors line
up as follows. The pure structural monitor reaches 100% safety, 100% usefulness, and
92% robustness against a covert adaptive attacker, at zero LLM cost. A pure LLM
monitor manages 69% safety, 82% usefulness, and 69% adaptive robustness, at 100% LLM
cost — it pays a model call every time and is the most jailbreakable of the set.
Taking the elementwise maximum of the two (the "hybrid") buys the best adaptive
robustness, 100%, and keeps safety at 100%, but its usefulness drops to 82% because
the LLM contributes false positives the structural layer never would. The gated
controller — which trusts the structural verdict whenever it is decisive and calls
the LLM only on the uncertain middle — restores usefulness to 100% and costs a model
call on just 9 of 75 actions (12%), at 85% safety and 77% adaptive robustness.

Two things follow. Adding the LLM is not free: it actively *lowers* usefulness
through false positives, which is the opposite of the intuition that more checking
is always safer. And there is a clean practical recommendation. Use the gated
controller as the default — full usefulness at 12% model cost; reach for the full
hybrid when adaptive attackers are genuinely expected and you will pay for the
robustness; and use the structural monitor alone as the auditable, zero-cost
baseline, always remembering that all three rest on the provenance signal.

## Disjoint failures, and an attacker that earned its keep

The third result is the one that makes the hybrid worth the bother. We run a single
fixed attacker, identically, against every monitor, and give it *declared
affordances*: it knows the structural rules and that the LLM scores text, it may
launder taint by dropping the PRIVATE label, and it may sanitize its cover text to
read as benign — but it cannot forge the user-confirmation record or send to an
allow-listed recipient, since either would defeat the point of the attack. Escalating
its effort from overt, to taint-laundering, to laundering-plus-sanitizing, the two
monitors fail in *opposite* directions. As the cover text is sanitized, the LLM
collapses — from 62% to 42% — because the text it reads has been engineered to look
fine. The structural monitor, which never reads the text, is unmoved by sanitization.
Their blind spots are disjoint, so the hybrid stays at 100% across the entire
frontier while each component alone has a regime where it breaks.

This is also where the optimizing attacker earned its place. Beyond the fixed
escalation, we ran a white-box attacker that searches the full space of declared
evasions and keeps the best one per attack. It found something the single
fixed-transform test had hidden: about 8% of attacks hit taint-only sinks such as a
generic `web_request` that, unlike the email sink, had no recipient backstop —
defeating both monitors at once and dropping structural safety to 92%. The fix was
concrete: we added a destination allow-list backstop, the `no-untrusted-destination`
rule, so that web hosts drawn from the user's own legitimate tasks are allow-listed
and everything else is caught. With it, structural and hybrid safety recover to 100%
at zero usefulness cost. That is exactly what an optimizing attacker is *for* — it
exposed a real hole that the gentler test missed and motivated a verified defense
rather than a hand-wave. (For honesty about the rest of the frontier: the LLM and
gated rows are essentially unchanged by the fix, since it targets the structural
layer, and their numbers carry the sampling variance of five-sample scoring across
runs — roughly 35% for the LLM and 65% for the gated controller under the full
optimizer.)

## The Vietnamese language gap: a confirmed null

We began with a clean hypothesis — that text-based LLM monitoring would degrade on
Vietnamese and on code-switched Vietnamese-English text — and it is false. On an
expanded set of sixteen attacks rendered in English, Vietnamese, and code-switched
form, the structural monitor scores 100% in all three languages, which is no surprise
since it reads typed fields rather than text. The interesting part is the LLM. A
frontier model showed no gap in an earlier run, and a *smaller* model, Claude Haiku,
shows none either: 88% on English, 94% on Vietnamese, 100% on code-switched. Not only
is there no degradation, the trend runs *opposite* to the hypothesis. So "LLM
monitoring degrades on Vietnamese" is not supported for capable or small models, and
we treat it as a confirmed negative result rather than burying it. The LLM's real
failure axis is adversarial text-sanitization, established above, not language. A
three-billion-parameter edge model remains the one untested regime, but the prior is
now strongly null, and we rest no headline on language. Vietnam grounds the threat
model; it does not carry a quantitative claim.

## The honest limits

A red-team built specifically to break the structural checker leaks two of three
hand-crafted attacks, and these are worth naming because they are the monitor's real
boundaries rather than hidden failures. Taint-laundering to an allow-listed alias
leaks, because taint must propagate across steps rather than per-call. The `find
-delete` construction evades a block-list of destructive commands — the lesson, which
we learned the hard way, is to allow-list commands rather than block-list them.
Sensitive data mislabeled as PUBLIC is merely downgraded rather than caught, because
data labels themselves need provenance. None of these are surprising once the design
is understood, and all of them point at the same missing piece: real, multi-step,
noisy provenance.

That points to the single most important limitation. Provenance is assumed, not
built. The one load-bearing assumption is that the system can distinguish
user-requested actions from injected ones, and if it cannot, every structural number
degrades — usefulness toward 5% — and the contribution becomes "here is the curve,"
not "here is 100%." Building and measuring a real, noisy provenance tracker is the
most important open problem this work leaves behind. Beyond that, the sample is
small (75 actions, six bilingual attacks; the confidence intervals are wide and the
results are directional rather than statistically tight), the live and real-model
rows depend on external software and an API key, and the scope is single-step action
authorization across the email, spreadsheet, banking, Slack, and travel suites —
multi-step taint propagation, command allow-listing, and document or chat agents are
out of scope, as is deepfake *detection*, since we treat claimed authority as
insufficient without trusted approval in the first place.

One limitation deserves to be stated on its own, because it marks the edge of what
this kind of monitor can ever do. SpecShield trusts the *user* as its authorization
anchor; its invariant is that untrusted *content* may not act without trusted *user*
approval. It therefore does not defend against a malicious or compromised *operator*
who drives the agent directly — the threat realized in the late-2025 AI-orchestrated
espionage campaign, in which a human operator decomposed an attack into
innocent-looking subtasks for an agent that held broad system access. Defending that
case requires a different and complementary invariant — authority separation:
least-privilege tool scoping so the agent never holds company-wide access,
segregation of duties so high-impact actions need a second independent approver,
out-of-band step-up authentication for irreversible actions, and aggregate
cross-action monitoring of rate, volume, and fan-out to catch sub-threshold
decompositions that no per-action check can see. SpecShield's content-provenance
invariant and this authority-separation invariant are orthogonal layers, and we
enforce only the former.

That, in fact, is the cleanest way to situate the whole project. A deployed
assistant needs defense in depth, and three layers answer three different questions.
Content moderation governs what the model *says*. SpecShield governs what an injected
document can make a trusted-user agent *do*. Authority separation governs what even
a malicious user or compromised operator can make the agent do. The layers are
genuinely orthogonal — content moderation never inspects actions, SpecShield trusts
the user, authority separation never reads content — and SpecShield is the missing
middle for the email and workflow assistants now being deployed, necessary but to be
composed with the other two, not mistaken for a standalone shield.

## What this changes, and what comes next

The implication worth carrying away is that structural authorization converts agent
safety into a measurable function of provenance quality, and that reframing matters
precisely because it makes the guarantee falsifiable and the residual explicit. You
can state exactly what an attacker must do — launder taint *and* sanitize text *and*
reach a backstop-free sink — and exactly where an LLM layer pays for itself: the
semantic residual the structural layer cannot prove. The disjoint-failure result is
the practical payoff, because a cheap gated hybrid inherits the structural monitor's
auditability and the LLM's semantic coverage while calling the model on only about a
tenth of actions.

The future work follows directly from the limits. The first and most important task
is to *derive* the provenance signal from trajectory structure rather than assign
it: we have already measured sensitivity to provenance quality by injecting label
noise, and the remaining step is to build a real, noisy provenance and dataflow
tracker and measure its accuracy in the wild. The second is to run a
three-billion-parameter open model as the monitor to locate the edge-model language
gap the frontier did not show. The third is to propagate taint across multi-step
trajectories, allow-list commands properly, and add the cross-action aggregate
monitoring that catches sub-threshold fraud. And the fourth, more speculative, is a
Lean or SMT backend for the decidable predicates.

In the end we built a structural trusted monitor that authorizes tool actions from
typed fields, dataflow taint, and approval provenance rather than payload text, and
we evaluated it as invariant enforcement on AgentDojo. It enforces the safety
invariant on every relevant attack at near-zero usefulness cost — but only given a
provenance signal, without which its usefulness collapses, and that dependence,
which prior information-flow results take for granted, is our main finding. Under an
optimizing attacker the structural and LLM monitors fail in disjoint ways, so a
cheap gated hybrid holds where each alone breaks. The takeaway for AI safety is that
structural authorization does not so much *solve* prompt injection as *relocate* it
to a measurable provenance problem — and that quantifying that relocation, rather
than reporting a single safety number, is the more honest and more useful
contribution.

---

## Reproducing the work

The repository (`github.com/<org>/specshield`) reproduces everything offline with
the standard library alone via `python3 -m specshield {test | demo | control |
attacker | bilingual | invariant | redteam}`; all control, attacker, invariant, and
bilingual numbers print their 95% Wilson confidence intervals, and the offline
threshold check (`control`) verifies 100% safety and usefulness at T=0.5 on the
ten-action sample with no dependencies. The live AgentDojo and real-model rows
require `pip install agentdojo anthropic` (Python ≥ 3.10) and an `ANTHROPIC_API_KEY`,
after which `python3 -m specshield invariant --live`, `control --live`, and `attacker
--live` reproduce the live figures; a small edge model can be substituted with
`SPECSHIELD_OLLAMA_MODEL=qwen2.5:3b python3 -m specshield bilingual`. The bundled data
are `agentdojo_sample.jsonl`, `vietnam_scenarios.jsonl`, and `bilingual_bec.jsonl`,
with the live tasks drawn from AgentDojo v1.2.1.

## References

The central prior work is Costa and Köpf et al., *Securing AI Agents with
Information-Flow Control* (Fides, arXiv:2505.23643, 2025); Debenedetti et al.,
*Defeating Prompt Injections by Design* (CaMeL, arXiv:2503.18813, 2025); and
Debenedetti et al., *AgentDojo* (arXiv:2406.13352, 2024), our evaluation substrate.
The monitoring and policy framing draws on *AgentWatcher* (arXiv:2604.01194, 2026),
the OWASP Top 10 for LLM Applications, OpenAI's *Designing AI Agents to Resist Prompt
Injection* (2026), and Anthropic's *Disrupting the first reported AI-orchestrated
cyber espionage campaign* (2025). The threat-model framing is grounded in the 2025
Verizon Data Breach Investigations Report and a set of Vietnam-specific sources on
deepfake-powered scams, AI-driven trade and invoice fraud, and the 2025 Law on
Cybersecurity (No. 116/2025/QH15), all web-verified June 2026. *All arXiv IDs and
external figures should be re-checked against primary sources before submission.*

## LLM usage statement

I used an LLM assistant to consolidate documentation, draft prose, and review
structure. All quantitative claims were produced by the project's own deterministic
CLI code and independently re-run; the report distinguishes offline-verifiable
results from those requiring the live AgentDojo harness and an API key. The final
manuscript was reviewed and edited by the author. Citation IDs and external figures
flagged above require verification against primary sources prior to submission.
