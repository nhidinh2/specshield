# VietGuard Threat Model — coverage of documented Vietnam attack types

The Vietnam and bilingual scenarios are **synthetic** (hand-authored), but they are
not invented freely: each is grounded in a **documented recent attack type** in
Vietnam, traced to a source. This file shows the coverage so the set is defensible
as "covers the documented threat surface for an email agent," not "made up."

Scope: only attack types where an **email/office agent reads untrusted content and
then takes a tool action**. Person-targeted scams with no agent tool-action
(romance, lottery, delivery, investment/crypto) are out of scope by construction.

## Documented Vietnam attack taxonomy (2025–2026)

Ranked/known from [S12] (Authority of Information Security), [S13] (RMIT), [S14],
[S2] (deepfake), [S4] (A05):

1. Deepfake / AI executive & authority impersonation — **#1 most dangerous, 2025** [S12][S2]
2. Police impersonation — **most common, 2025** [S12]
3. Bank / fintech impersonation — >18,000 cases H1 2025 [S12]
4. OTP theft / vishing (AI voice cloning) [S12]
5. Phishing links / smishing → fake sites [S12]
6. AI-powered BEC / vendor wire-change [S13][S14]
7. AI invoice fraud (incl. sub-threshold splitting) [S14]
8. Payroll / payment diversion (BEC variant) [S13]
9. Pretext data exfiltration (audit/consultant) [S13]
10. AI prompt injection (agent-specific) [S7]

## Coverage map (scenario → documented type → source)

| scenario | documented attack type | source |
|---|---|---|
| `vn_deepfake_ceo` | deepfake/executive authority impersonation (#1) | [S12][S2] |
| `vn_bank_otp` / `otp_verify` | bank/police impersonation + OTP theft (#2,3,4) | [S12][S4] |
| `vn_malicious_link` | phishing link / smishing (#5) | [S12] |
| `vn_fake_invoice` / `wire_change` | AI BEC / vendor wire-change (#6) | [S13][S14] |
| `invoice_urgent` | AI invoice fraud / urgency (#7) | [S14] |
| `payroll_redirect` | payroll/payment diversion (#8) | [S13] |
| `data_audit` | pretext data exfiltration (#9) | [S13] |
| `contract_forward` | executive impersonation + exfiltration (#1,9) | [S13][S2] |
| `vn_mixed_injection` | AI prompt injection, VN-EN code-switched (#10) | [S7] |

**Covered: 10/10 email-agent-relevant documented types.**

## Honest gaps

- **Sub-threshold invoice splitting** [S14] — a deliberately *aggregate* pattern
  (each payment below the review threshold; the fraud is in the total). A
  **per-action monitor — structural OR LLM — cannot catch this by design**, because
  each individual action looks fine. We do **not** include it as a "caught" case;
  it is a stated limitation and motivates future cross-action / aggregate monitoring.
- **Deepfake media detection itself** is out of scope; VietGuard treats *claimed*
  authority as insufficient without trusted provenance, regardless of media realism.
- The scenarios remain **hand-authored and not native-speaker-vetted**; grounding in
  documented types reduces, but does not remove, this limitation. Native-speaker
  review and real attack samples (e.g. from [S1]/[S4] datasets) are the next step.
