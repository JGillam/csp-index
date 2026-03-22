# CSP Index: A Risk-Based Index for Content Security Policies

> **Status:** Proposal / RFC
> **Version:** 0.1.0
> **Author:** Jason Gillam

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Design Goals](#2-design-goals)
3. [Scoring Model Overview](#3-scoring-model-overview)
4. [Directive Categories and Weights](#4-directive-categories-and-weights)
5. [Per-Category Scoring Rubrics](#5-per-category-scoring-rubrics)
6. [Directive Fallback Logic](#6-directive-fallback-logic)
7. [Complementary Header Modifiers](#7-complementary-header-modifiers)
8. [Aggregate Index Formula](#8-aggregate-index-formula)
9. [Worked Examples](#9-worked-examples)
10. [Edge Cases and Special Handling](#10-edge-cases-and-special-handling)
11. [Open-Source Tooling](#11-open-source-tooling)
12. [Limitations and Future Work](#12-limitations-and-future-work)
13. [References](#13-references)

---

## 1. Motivation

Content Security Policy (CSP) is one of the most powerful browser-enforced defenses against client-side attacks — but also one of the most frequently misconfigured. The current state of the art in CSP evaluation is largely binary: either a CSP header is present or it isn't. Tools like security scanners and header graders treat the existence of a CSP as a pass condition, with little or no differentiation between a policy like:

```
Content-Security-Policy: script-src *; object-src *
```

and:

```
Content-Security-Policy: script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

These two policies represent radically different threat surfaces. The first offers essentially no XSS protection and is arguably worse than no CSP at all (because it creates a false sense of security). The second is close to optimal by current best-practice standards.

The goal of **CSP Index** is to replace this pass/fail model with a continuous, weighted **risk index from 1 to 10**, where:

- **1** = minimal risk (policy is well-formed and restrictive across all meaningful attack surfaces)
- **10** = maximum risk (no CSP, or a policy so permissive it provides no meaningful protection)

This index is:
- **Fully automatic** — computed from the raw CSP header string with no manual inputs
- **Deterministic** — the same input always produces the same output
- **Transparent** — every point contribution is traceable to a specific directive value
- **Proportional** — categories are weighted by the relative impact of exploitation

The scoring model draws from empirical research on CSP adoption and effectiveness, the W3C CSP Level 3 specification, and OWASP guidelines.

---

## 2. Design Goals

**Automatic and verifiable.** The scorer takes a raw `Content-Security-Policy` header string (and optionally a set of other HTTP response headers) and returns a numeric risk index. No human judgment is required.

**Attack-surface proportionality.** Not all CSP directives protect against equally severe attacks. Script injection enables arbitrary code execution; style injection enables UI redressing. These categories carry different weights.

**Browser-accurate semantics.** Certain directive interactions change their effective meaning in browsers. For example, `'unsafe-inline'` is ignored by browsers when a valid nonce or hash is present in the same directive. The scorer must reflect actual browser behavior, not a naive keyword search.

**Graceful degradation.** A policy that protects 5 out of 6 attack categories should score significantly better than one that protects none. The scoring should not cliff-edge on a single missing directive.

**Composable with other headers.** Certain HTTP response headers (e.g., `X-Frame-Options`) provide overlapping or complementary protections. These are acknowledged as index modifiers with clear limits, and must not fully substitute for the corresponding CSP directive.

---

## 3. Scoring Model Overview

The scoring model has three layers:

```
Raw CSP header string
        │
        ▼
┌───────────────────────────────────────────────────┐
│  Layer 1: Directive Parsing & Fallback Resolution │
│  Resolve effective source lists per category,     │
│  applying default-src fallback where applicable.  │
└───────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────┐
│  Layer 2: Per-Category Risk Scoring               │
│  Each category receives a normalized risk score   │
│  in [0.0, 1.0] based on a defined rubric.        │
└───────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────┐
│  Layer 3: Weighted Aggregation + Modifiers        │
│  Weighted sum of category scores, adjusted by     │
│  any applicable header modifiers, scaled to 1–10. │
└───────────────────────────────────────────────────┘
```

The final index value is a floating-point number rounded to one decimal place, in the range [1.0, 10.0].

---

## 4. Directive Categories and Weights

The scoring system covers six directive categories, each corresponding to a distinct attack surface. Weights reflect the relative exploitability and impact of weaknesses in that area.

| Category | Primary Directive(s) | Fallback | Weight | Attack Surface |
|---|---|---|---|---|
| **Script Execution** | `script-src` | `default-src` | 0.35 | Cross-site scripting (XSS); arbitrary JS execution |
| **Object / Plugin Execution** | `object-src` | `default-src` | 0.15 | Flash/plugin-based code execution |
| **Frame Embedding** | `frame-ancestors` | *(none)* | 0.15 | Clickjacking; UI redress attacks |
| **Form Actions** | `form-action` | *(none)* | 0.15 | Credential exfiltration via form hijacking |
| **Base URI** | `base-uri` | *(none)* | 0.10 | DOM base-tag injection; relative URL hijacking |
| **Style Injection** | `style-src` | `default-src` | 0.10 | CSS injection; data exfiltration via side channel |
| **Total** | | | **1.00** | |

### Rationale for Weights

**Script Execution (0.35):** JavaScript injection is the predominant web attack vector. An unrestricted `script-src` renders all other CSP directives largely academic — an attacker with arbitrary JS execution can bypass form controls, read cookies, and exfiltrate data at will.

**Object / Plugin Execution (0.15):** Browser plugins (Flash, Java, Silverlight) are now effectively extinct in modern browsers, but `object-src` still controls HTML `<object>` and `<embed>` elements. A missing or permissive `object-src` allows plugin-based code execution in legacy environments and data-URI embedding in modern ones. Its weight reflects declining relevance balanced against residual risk.

**Frame Embedding (0.15):** The absence of `frame-ancestors` leaves a site open to clickjacking attacks, where an attacker overlays the target page in a transparent iframe to hijack user interactions. This is a well-understood, high-reliability attack class.

**Form Actions (0.15):** Without `form-action`, a page's forms can be hijacked to submit credentials to an attacker-controlled endpoint. This is especially relevant in the context of XSS — even if script injection is restricted, unrestricted form actions provide an alternative exfiltration path.

**Base URI (0.10):** `base-uri` prevents attackers from injecting a `<base>` tag to redirect all relative URLs (including script sources) to an attacker-controlled domain. The risk is real but requires a pre-existing HTML injection primitive.

**Style Injection (0.10):** CSS injection can leak data via attribute selectors and timing attacks, and can be used to redress UI elements. However, CSS injection without JavaScript is a more limited attack channel, justifying a lower weight.

> **Out of scope (v1):** `connect-src`, `img-src`, `media-src`, `worker-src`, `manifest-src`, and `navigate-to` are not scored in this version. These directives have meaningful security implications but are either lower-impact, less consistently deployed, or require more contextual knowledge to score accurately. They are candidates for future scoring categories.

---

## 5. Per-Category Scoring Rubrics

Each category returns a **normalized risk score** in **[0.0, 1.0]**, where 0.0 means no risk contribution and 1.0 means maximum risk. The rubric for each category is a decision tree evaluated against the effective source list for that directive.

### Terminology

- **Effective directive:** The value actually evaluated for a given category, after applying fallback logic (see Section 6).
- **Absent:** No effective directive is defined (neither the specific directive nor `default-src` covers it, where applicable).
- **Wildcard source (`*`):** Matches any HTTP/HTTPS URL, effectively disabling the restriction.
- **Active `'unsafe-inline'`:** `'unsafe-inline'` is present and *not* neutralized by a nonce or hash (see browser semantic note in Section 6).
- **Nonce/hash protected:** At least one nonce (`'nonce-...'`) or hash (`'sha256-...'`, `'sha384-...'`, `'sha512-...'`) is present in the source list.

---

### 5.1 Script Execution

Evaluate `script-src` (fallback: `default-src`).

| Condition | Risk Score |
|---|---|
| Directive is absent | 1.00 |
| Directive present with wildcard (`*`) source | 0.95 |
| Directive present with `data:` or `blob:` scheme | 0.85 |
| Active `'unsafe-inline'` + active `'unsafe-eval'` | 0.80 |
| Active `'unsafe-inline'` (no nonce/hash, no `'unsafe-eval'`) | 0.70 |
| `'unsafe-eval'` only (no `'unsafe-inline'`) | 0.55 |
| Specific-domain allowlist, no nonce/hash, no unsafe directives | 0.45 |
| Nonce/hash protected, no wildcards, no active unsafe directives | 0.20 |
| `'strict-dynamic'` + nonce/hash, no active unsafe directives | 0.10 |
| `'strict-dynamic'` + nonce/hash + `require-trusted-types-for 'script'` | 0.00 |

**Note:** Rows are evaluated top-to-bottom; the first matching condition applies.

**Implementation note:** `'unsafe-inline'` is considered *active* only if no nonce or hash is present in the same directive. Per the CSP specification, browsers ignore `'unsafe-inline'` when a valid nonce or hash is present. Tools must implement this semantic to avoid penalizing policies that correctly use nonces alongside `'unsafe-inline'` for backward compatibility.

---

### 5.2 Object / Plugin Execution

Evaluate `object-src` (fallback: `default-src`).

| Condition | Risk Score |
|---|---|
| Directive is absent | 1.00 |
| Directive present with wildcard (`*`) source | 0.90 |
| Directive present with `data:` scheme | 0.75 |
| Specific-domain allowlist (one or more external origins) | 0.35 |
| `'self'` only | 0.15 |
| `'none'` | 0.00 |

---

### 5.3 Frame Embedding

Evaluate `frame-ancestors`. **This directive does not fall back to `default-src`.**

| Condition | Risk Score |
|---|---|
| `frame-ancestors` is absent | 1.00 |
| `frame-ancestors *` (explicit wildcard) | 0.90 |
| `frame-ancestors` with external origin allowlist (3+ entries) | 0.50 |
| `frame-ancestors` with external origin allowlist (1–2 entries) | 0.30 |
| `frame-ancestors 'self'` (possibly with one trusted origin) | 0.10 |
| `frame-ancestors 'none'` | 0.00 |

---

### 5.4 Form Actions

Evaluate `form-action`. **This directive does not fall back to `default-src`.**

| Condition | Risk Score |
|---|---|
| `form-action` is absent | 1.00 |
| `form-action *` (explicit wildcard) | 0.90 |
| `form-action` with external origin allowlist (3+ entries) | 0.50 |
| `form-action` with external origin allowlist (1–2 entries) | 0.30 |
| `form-action 'self'` (possibly with one trusted origin) | 0.05 |
| `form-action 'none'` | 0.00 |

---

### 5.5 Base URI

Evaluate `base-uri`. **This directive does not fall back to `default-src`.**

| Condition | Risk Score |
|---|---|
| `base-uri` is absent | 1.00 |
| `base-uri *` (explicit wildcard) | 0.90 |
| `base-uri` with external origin allowlist | 0.40 |
| `base-uri 'self'` | 0.05 |
| `base-uri 'none'` | 0.00 |

---

### 5.6 Style Injection

Evaluate `style-src` (fallback: `default-src`).

| Condition | Risk Score |
|---|---|
| Directive is absent | 1.00 |
| Directive present with wildcard (`*`) source | 0.90 |
| Active `'unsafe-inline'` (no nonce/hash) | 0.65 |
| Specific-domain allowlist, no nonce/hash, no `'unsafe-inline'` | 0.35 |
| Nonce/hash protected, no wildcards, no active `'unsafe-inline'` | 0.10 |
| `'none'` | 0.00 |

---

## 6. Directive Fallback Logic

The CSP specification defines `default-src` as a fallback for most fetch directives — but not all. This distinction is critical for accurate scoring.

### Directives that fall back to `default-src`

If the specific directive is absent, the scorer uses the `default-src` value as the effective directive:

- `script-src`
- `style-src`
- `object-src`
- `img-src`, `media-src`, `connect-src` (informational; not scored in v1)

### Directives that do NOT fall back to `default-src`

These directives are navigation/action controls, not fetch controls. If absent, they are simply unset — regardless of what `default-src` says:

- `frame-ancestors`
- `form-action`
- `base-uri`
- `navigate-to`

This is a common source of misconfiguration: a site may have a strict `default-src` and believe it is protected against clickjacking, when in fact `frame-ancestors` must be explicitly specified.

### Resolution algorithm

```
function effectiveDirective(csp, directiveName, hasFallback):
    if directiveName in csp.directives:
        return csp.directives[directiveName]
    if hasFallback and 'default-src' in csp.directives:
        return csp.directives['default-src']
    return ABSENT
```

---

## 7. Complementary Header Modifiers

Several HTTP response headers provide security controls that overlap with specific CSP directives. The scorer acknowledges these modifiers as **risk reductions applied to specific category scores** — but with strict limits.

The guiding principle is:

> Modifier headers provide defense-in-depth, not a replacement for CSP. A missing CSP directive cannot be fully compensated by an alternative header. Modifiers apply a fractional risk reduction, capped at 40% of the category's maximum risk contribution.

### Defined Modifiers

| Header | Value(s) | Applies to Category | Max Risk Reduction |
|---|---|---|---|
| `X-Frame-Options` | `DENY` | Frame Embedding | 40% |
| `X-Frame-Options` | `SAMEORIGIN` | Frame Embedding | 25% |
| `Permissions-Policy` | any value | Style Injection | 5% |

#### `X-Frame-Options: DENY` or `SAMEORIGIN`

`X-Frame-Options` is the legacy predecessor to `frame-ancestors` and is broadly supported. When `frame-ancestors` is absent and `X-Frame-Options: DENY` is present, clickjacking risk is meaningfully reduced. The 40% cap reflects that:

1. `X-Frame-Options` is not honored in all embedding contexts (e.g., `<object>` elements in some older browsers).
2. It cannot express the full range of allowlists that `frame-ancestors` supports.
3. Policies that rely solely on `X-Frame-Options` represent an outdated configuration.

When `frame-ancestors` is **already defined**, `X-Frame-Options` provides no additional score modifier — the CSP directive is authoritative in modern browsers, and the presence of a redundant header is irrelevant to risk.

#### `Permissions-Policy`

The `Permissions-Policy` header restricts access to browser APIs (camera, microphone, geolocation, etc.). Its relationship to CSP is indirect — it reduces the blast radius of a successful XSS by limiting what a script can do — but it does not constrain script execution itself. The 5% modifier reflects this marginal, indirect benefit.

### Modifier Handling: The Double-Counting Problem

A key challenge with modifier headers is avoiding the inflation of protection credit. Consider a policy where:

- `frame-ancestors` is absent → base risk score for Frame Embedding = 1.0
- `X-Frame-Options: DENY` is present → modifier reduces this to 0.6

The problem arises when a developer then adds `frame-ancestors 'none'` to the CSP. The frame risk drops to 0.0 from the rubric, and the `X-Frame-Options` modifier should no longer apply. The system handles this cleanly by rule:

**Modifier reductions are only applied when the corresponding CSP directive falls back to an absent or permissive state.** Specifically:

- If a category's rubric score is already ≤ 0.10 (i.e., the CSP directive is already doing its job), no modifier is applied.
- If a category's rubric score is > 0.10, the modifier is applied to the rubric score, capped at 40% reduction.

This ensures modifiers never inflate a score below what a correct CSP directive already achieves, and never mask the absence of a directive entirely.

### Why Not More Modifiers?

Headers like `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and `Strict-Transport-Security` are general security hygiene but have minimal bearing on CSP-specific risk. Including them here would dilute the CSP-specific signal of the index. These headers are better evaluated by a general HTTP security header scorer (such as securityheaders.com) that operates alongside CSP Index.

---

## 8. Aggregate Index Formula

### Step 1: Compute per-category raw risk scores

For each of the six categories, apply the relevant rubric to get a raw risk score `r_i ∈ [0.0, 1.0]`.

### Step 2: Apply modifier adjustments

For each category where a modifier applies and the raw score > 0.10:

```
r_i_adjusted = r_i × (1 - min(modifier_reduction, 0.40))
```

### Step 3: Compute weighted sum

```
weighted_sum = Σ (w_i × r_i_adjusted)
```

Where `w_i` are the category weights defined in Section 4 and sum to 1.0.

### Step 4: Scale to [1.0, 10.0]

```
risk_index = 1.0 + (weighted_sum × 9.0)
```

This maps `weighted_sum = 0.0` (all categories perfectly protected) to a final index of **1.0**, and `weighted_sum = 1.0` (all categories maximally risky) to a final index of **10.0**.

### Step 5: Round

The final index is reported to one decimal place:

```
final_index = round(risk_index, 1)
```

### Index Interpretation Table

| Index Range | Risk Level | Interpretation |
|---|---|---|
| 1.0 – 2.5 | Low | Strong, restrictive CSP. Minor improvements possible. |
| 2.6 – 4.5 | Moderate | Meaningful protections in place but notable gaps exist. |
| 4.6 – 6.5 | High | Significant weaknesses; several attack surfaces exposed. |
| 6.6 – 8.5 | Critical | CSP provides little practical protection; likely a checkbox policy. |
| 8.6 – 10.0 | Severe | No CSP, or a policy so permissive it is effectively absent. |

---

## 9. Worked Examples

### Example A: Modern Nonce-Based Policy

```
Content-Security-Policy:
  script-src 'nonce-abc123' 'strict-dynamic';
  object-src 'none';
  style-src 'self';
  frame-ancestors 'self';
  form-action 'self';
  base-uri 'none'
```

| Category | Effective Directive | Condition | Score | Weight | Contribution |
|---|---|---|---|---|---|
| Script Execution | `script-src` | strict-dynamic + nonce, no unsafe | 0.10 | 0.35 | 0.035 |
| Object/Plugin | `object-src` | `'none'` | 0.00 | 0.15 | 0.000 |
| Frame Embedding | `frame-ancestors` | `'self'` | 0.10 | 0.15 | 0.015 |
| Form Actions | `form-action` | `'self'` | 0.05 | 0.15 | 0.008 |
| Base URI | `base-uri` | `'none'` | 0.00 | 0.10 | 0.000 |
| Style Injection | `style-src` | `'self'`, no unsafe-inline | 0.35 | 0.10 | 0.035 |
| **Total** | | | | | **0.093** |

**CSPit Index:** `1.0 + (0.093 × 9.0) = 1.84` → **1.8 / 10.0 (Low)**

---

### Example B: Checkbox CSP (Common Misconfiguration)

```
Content-Security-Policy:
  default-src 'self' 'unsafe-inline' 'unsafe-eval' https:
```

| Category | Effective Directive | Condition | Score | Weight | Contribution |
|---|---|---|---|---|---|
| Script Execution | `default-src` | unsafe-inline + unsafe-eval | 0.80 | 0.35 | 0.280 |
| Object/Plugin | `default-src` | External HTTPS origins via `https:` wildcard | 0.90 | 0.15 | 0.135 |
| Frame Embedding | absent | Not defined; no fallback | 1.00 | 0.15 | 0.150 |
| Form Actions | absent | Not defined; no fallback | 1.00 | 0.15 | 0.150 |
| Base URI | absent | Not defined; no fallback | 1.00 | 0.10 | 0.100 |
| Style Injection | `default-src` | Active unsafe-inline | 0.65 | 0.10 | 0.065 |
| **Total** | | | | | **0.880** |

**CSPit Index:** `1.0 + (0.880 × 9.0) = 8.92` → **8.9 / 10.0 (Severe)**

---

### Example C: Absent CSP with X-Frame-Options

```
(No CSP header present)
X-Frame-Options: DENY
```

| Category | Condition | Score | Modifier | Adjusted | Weight | Contribution |
|---|---|---|---|---|---|---|
| Script Execution | Absent | 1.00 | none | 1.00 | 0.35 | 0.350 |
| Object/Plugin | Absent | 1.00 | none | 1.00 | 0.15 | 0.150 |
| Frame Embedding | Absent | 1.00 | X-Frame-Options: DENY (−40%) | 0.60 | 0.15 | 0.090 |
| Form Actions | Absent | 1.00 | none | 1.00 | 0.15 | 0.150 |
| Base URI | Absent | 1.00 | none | 1.00 | 0.10 | 0.100 |
| Style Injection | Absent | 1.00 | none | 1.00 | 0.10 | 0.100 |
| **Total** | | | | | | **0.940** |

**CSPit Index:** `1.0 + (0.940 × 9.0) = 9.46` → **9.5 / 10.0 (Severe)**

The `X-Frame-Options` header meaningfully reduces clickjacking risk but has minimal effect on the aggregate index — a correct signal that the overall posture is still severely deficient.

---

## 10. Edge Cases and Special Handling

### No CSP header present

All categories are treated as absent. The index will typically fall between 9.0 and 10.0, depending on modifier headers present.

### CSP-Report-Only

`Content-Security-Policy-Report-Only` does not enforce any restrictions in the browser — it only reports violations. A site with only a `Report-Only` policy has no active CSP protection. The scorer must treat `Report-Only` as absent for scoring purposes, though it may note the presence of a reporting policy separately.

### Multiple CSP headers

Per the CSP specification, when multiple `Content-Security-Policy` headers are present, the browser applies the intersection of all policies (i.e., the most restrictive across all headers). The scorer should parse all present CSP headers and use the most restrictive effective value per directive.

### `'nonce-'` token validity

The scorer does not validate nonce randomness or length beyond confirming the presence of the `'nonce-'` prefix. Per-request nonce generation is a deployment concern, not a syntactic one. Static nonces (i.e., the same value in every response) do represent a real weakening, but detection requires dynamic analysis outside the scope of a header-based scorer.

### `'unsafe-inline'` neutralization by nonce/hash

Per the CSP Level 3 specification:

> If a policy contains a `nonce-source` or `hash-source`, the `'unsafe-inline'` keyword is ignored.

The scorer must implement this semantic. The presence of `'nonce-abc123'` in `script-src` means that `'unsafe-inline'` — if also present — is **not active** and should not trigger the unsafe-inline penalty.

### `'strict-dynamic'`

When `'strict-dynamic'` is present, the browser ignores both origin allowlists and `'unsafe-inline'` in favor of nonce/hash trust propagation. The scorer should recognize `'strict-dynamic'` as an upgrade from allowlist-based CSP, but only credit it when a nonce or hash is also present (otherwise `'strict-dynamic'` alone is meaningless).

### Scheme-only sources (`https:`, `http:`, `data:`, `blob:`)

`https:` as a source is nearly as permissive as `*` for `script-src` — it allows loading scripts from any HTTPS URL. The scorer should treat `https:` as equivalent to a wildcard for script and object sources. The `data:` and `blob:` schemes are particularly dangerous in `script-src` as they enable inline script execution via data URIs.

---

## 11. Open-Source Tooling

### Reference Implementation

The reference implementation (to be co-located in this repository) will provide:

- A Python library (`csp_index`) with a single primary interface:
  ```python
  from csp_index import compute_index

  result = compute_index(
      csp_header="script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; ...",
      other_headers={
          "X-Frame-Options": "DENY"
      }
  )

  print(result.index)          # 2.1
  print(result.risk_level)     # "Low"
  print(result.category_scores)  # {"script_execution": 0.10, ...}
  print(result.modifiers_applied)  # [{"header": "X-Frame-Options", ...}]
  ```

- A command-line interface:
  ```bash
  csp-index --url https://example.com
  csp-index --header "script-src 'nonce-abc' 'strict-dynamic'"
  csp-index --file headers.json
  ```

- A JSON output mode for pipeline integration:
  ```json
  {
    "index": 2.1,
    "risk_level": "Low",
    "category_scores": {
      "script_execution": { "raw": 0.10, "adjusted": 0.10, "weight": 0.35 },
      ...
    },
    "modifiers_applied": [],
    "flags": ["style_src_no_nonce"]
  }
  ```

### Integration with `csp-analysis`

The `csp-analysis` project (a companion tool for large-scale CSP collection and classification) provides a complementary dataset of CSP adoption patterns across the web. The `csp_index` library is designed to be callable from `csp-analysis` pipelines, adding a risk index column to bulk CSP datasets for statistical analysis.

### Suggested Use Cases

- **CI/CD pipelines:** Assert that your application's CSP never regresses beyond a target index (e.g., `--max-index 3.5`).
- **Security audits:** Provide clients with a reproducible, quantified CSP risk rating alongside remediation guidance.
- **Research:** Score large CSP datasets to analyze industry-wide trends in CSP quality over time.
- **Developer tooling:** IDE plugins, browser extensions, or HTTP proxy integrations that surface CSP risk index values in real time.

---

## 12. Limitations and Future Work

### Known Limitations

**Header-only analysis.** This model scores the CSP header as a static string. It does not account for whether nonces are actually randomized per-request, whether allowlisted domains serve attacker-controllable content (a major practical weakness known as "CSP bypass via trusted CDN"), or whether the policy is actually enforced vs. report-only in practice.

**No context sensitivity.** A `form-action 'self'` score of 0.05 is the same regardless of whether the site handles authentication forms or purely informational content. Risk scoring in context requires application-level knowledge beyond the header.

**Allowlist quality.** The rubric penalizes any external-domain allowlist less than `'self'`-only policies, but it cannot distinguish between `script-src https://cdn.trusted-partner.com` and `script-src https://an-attacker-can-serve-content-here.com`. In practice, CDN-hosted script sources are a common CSP bypass vector; detecting this requires cross-referencing allowlisted domains against known-exploitable endpoints.

**Dynamic policies.** Server-side rendering with per-request nonces, meta-tag CSP overrides, and ServiceWorker-managed policies are outside the scope of header-level static analysis.

### Future Scoring Categories (v2 Candidates)

- `connect-src`: Restricts outbound fetch/XHR/WebSocket connections. Relevant for data exfiltration post-XSS.
- `worker-src`: Controls Web Worker and SharedWorker sources. Emerging attack surface for isolation bypasses.
- `navigate-to`: Restricts navigation targets. Useful for containing open-redirect abuse.
- Allowlist quality scoring: Penalize `script-src` allowlists that include known CDNs with user-uploadable content (e.g., domains that have been documented as CSP bypass vectors).
- SRI correlation: Sites that use Subresource Integrity alongside CSP get additional risk reduction credit.

### Index Calibration

The weights and rubric thresholds in this document are an initial proposal based on expert judgment and empirical analysis of CSP adoption data. They should be validated and potentially recalibrated against:

- Known-exploited CSP configurations from public CVE databases
- Expert consensus from the web security research community
- Correlation analysis against real-world incident data

Contributions to calibration methodology are welcome.

---

## 13. References

- [W3C Content Security Policy Level 3 Specification](https://www.w3.org/TR/CSP3/)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [Bypassing CSP with Policy Injection (PortSwigger Research)](https://portswigger.net/research/bypassing-csp-with-policy-injection)
- [Mitigating XSS with a Strict Content Security Policy (Google)](https://csp.withgoogle.com/docs/strict-csp.html)
- [CSP Is Dead, Long Live CSP! — Weichselbaum et al. (CCS 2016)](https://dl.acm.org/doi/10.1145/2976749.2978363)
- MDN Web Docs: [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
