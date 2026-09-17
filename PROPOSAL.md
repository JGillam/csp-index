# CSP Index: Putting a Number on "Yes, We Have a CSP"

> **Status:** Proposal / RFC
> **Version:** 0.2.0
> **Author:** Jason Gillam

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [What This Scores, and What It Does Not](#2-what-this-scores-and-what-it-does-not)
3. [Design Goals](#3-design-goals)
4. [The Seven Categories and Their Weights](#4-the-seven-categories-and-their-weights)
5. [Resolving the Policy Before You Score It](#5-resolving-the-policy-before-you-score-it)
6. [The Rubrics](#6-the-rubrics)
7. [Other Headers as Modifiers](#7-other-headers-as-modifiers)
8. [How the Number Gets Made](#8-how-the-number-gets-made)
9. [Worked Examples](#9-worked-examples)
10. [Leftover Edge Cases](#10-leftover-edge-cases)
11. [Tooling](#11-tooling)
12. [Limitations and Future Work](#12-limitations-and-future-work)
13. [What Changed Since 0.1](#13-what-changed-since-01)
14. [References](#14-references)

---

## 1. Motivation

On a fair number of the web application tests I run, the response headers include a `Content-Security-Policy`, and I have learned not to get my hopes up when I see one. More often than not the policy turns out to be something like `default-src 'self' 'unsafe-inline' 'unsafe-eval' https:`, which stops approximately nothing I care about. I can only guess at how it got there (my guess is usually that a scanner or an auditor said "add a CSP," and somebody did exactly that and no more), but the pattern is consistent: a nearly or completely useless CSP that could easily be doing so much more to protect the application. The XSS I find later in the test fires happily under it.

Compare these two headers:

```
Content-Security-Policy: script-src *; object-src *
```

```
Content-Security-Policy: script-src 'nonce-VOSYT20SImp81YScafJexg==' 'strict-dynamic';
                         object-src 'none'; base-uri 'none'; form-action 'self';
                         frame-ancestors 'none'
```

A scanner that reports "CSP: present" treats those as the same result. They are not remotely the same result. The first one is no better than having no CSP at all, and it is arguably more annoying than having none, because a checkbox got ticked and everyone moved on. (I am not going to claim it is *worse* than no CSP. Under any sane model it cannot be, and I said otherwise in 0.1, which was sloppy.) The second one is close to what current best practice actually asks for.

The other half of this comes from data collection. I have been gathering CSP headers at scale in a companion project, [csp-lab](https://github.com/JGillam/csp-lab), which started life as "experimenting with gathering CSP data / statistics" and grew a six-component classification framework in `docs/csp-component-classifications.md`. That framework was applied across a dataset of 750,000+ sites, and the first six of the seven categories in this document grew directly out of it. Once you have a few hundred thousand policies in a table, "present" and "absent" stop being useful columns and you start wanting a number you can sort on. [Placeholder: distribution findings from that dataset, once they are written up.]

So the goal here is a continuous, weighted **score from 0 to 10**, where higher is better. A 10.0 means the header is about as restrictive as a header can be. A 0.0 means there is no CSP, or there is one that may as well not be there. Everything in between is meant to be traceable back to a specific directive value, so that when the number drops, you can point at the line that did it.

---

## 2. What This Scores, and What It Does Not

Let me scope this before anyone gets the wrong idea about what a 10.0 means.

The CSP Index scores **a header string**. It looks at the `Content-Security-Policy` header (plus a couple of complementary headers, see Section 7) and returns a number describing how much of the client-side attack surface that policy actually closes. That is the whole job.

It does not score the site. A policy can earn a 9.5 and sit in front of an application riddled with stored XSS, SQL injection, and a broken authorization model, and the score will still say 9.5, because the score is telling you about the policy and not about the code behind it. It also cannot tell you whether the nonce you are looking at is freshly generated per request (though it makes one cheap attempt, see rule 8), whether an allowlisted CDN happens to host attacker-controllable JSONP, or whether the policy is even reachable on the pages that matter.

So the claim here is a narrow one: for the one specific question of how much of a policy's protective value is actually there, you should be able to get a repeatable number instead of a yes or a no.

One more scoping note: the CSP Index is deliberately **not** a remediation tool. It tells you where the risk is concentrated, and the category breakdown will point you at the directive, but it does not generate a suggested policy for you. That is a different tool, and Google's CSP Evaluator already does a decent job of it.

---

## 3. Design Goals

**Automatic and verifiable.** The scorer takes a raw header string (and optionally a few other response headers) and returns a number. No human judgment at scoring time, and no configuration knobs, because a knob is just a way for two people to get two different answers for the same header.

**Attack-surface proportionality.** CSP directives do not protect against equally severe things. Script injection gets you arbitrary code execution in the user's session; style injection gets you a fairly constrained side channel and some UI redress. Those should not carry the same weight, and in this model they do not.

**Browser-accurate semantics.** A surprising amount of CSP scoring in the wild is a keyword search, which is how you end up penalizing a policy for `'unsafe-inline'` that browsers are ignoring anyway because a nonce is present in the same directive. The scorer has to model what the browser does with the source list, not what the string looks like. Most of Section 5 exists because of this goal.

**Graceful degradation, for six of the seven categories.** A policy that covers six attack surfaces and misses one should score noticeably better than a policy that covers none, and the weighted sum handles that. **Script execution is the deliberate exception.** It is allowed to cliff-edge, and it does, via the cap in Section 8. This was the single biggest correction from 0.1, where I said in prose that open script execution makes everything else academic and then built a formula that disagreed with me.

**Composable with other headers, within limits.** A few response headers (`X-Frame-Options`, mainly) genuinely overlap with a CSP directive. Those are recognized as modifiers on a specific category value, they never apply when the CSP directive that supersedes them is present, and they cannot move the score on their own.

---

## 4. The Seven Categories and Their Weights

Seven categories, each mapping to a distinct attack surface, with weights summing to 1.00.

| Category | Primary directive(s) | Falls back to | Weight | Attack surface |
|---|---|---|---|---|
| Script Execution | `script-src-elem`, `script-src-attr`, `script-src` | `default-src` | 0.40 | XSS; arbitrary JS in the user's session |
| Object / Plugin | `object-src` | `default-src` | 0.05 | `<object>` / `<embed>` content, `data:` embedding |
| Frame Embedding | `frame-ancestors` | *(none)* | 0.15 | Clickjacking and UI redress |
| Form Actions | `form-action` | *(none)* | 0.15 | Credential exfiltration by form hijacking |
| Base URI | `base-uri` | *(none)* | 0.10 | `<base>` injection; relative URL hijacking |
| Style Injection | `style-src-elem`, `style-src-attr`, `style-src` | `default-src` | 0.10 | CSS injection, selector-based data leaks, UI redress |
| Frame Content | `frame-src` | `child-src`, then `default-src` | 0.05 | Injected iframes; in-page phishing overlays |
| **Total** | | | **1.00** | |

### Why these weights

**Script Execution (0.40).** This went up from 0.35 in 0.1, and honestly it could be argued higher still. JavaScript injection is the attack the whole mechanism was built to contain. If an attacker can run script in your origin, then your `form-action` is decorative (they can rewrite the form, or skip the form and post the credentials directly), your `base-uri` is decorative, and your `frame-ancestors` is beside the point because they are already inside. The weight is only half the story here; the cap in Section 8 does the heavy lifting. That is why the new Frame Content category is funded out of this weight (0.45 down to 0.40): with the cap in place, a nudge to the script weight changes very little, because for a bad script directive the cap is already what sets the number.

**Object / Plugin (0.05).** Down hard from 0.15, and I expect this to be the least controversial change in the document. Flash is gone, Java applets are gone, Silverlight is gone. What is left is `<object>` and `<embed>` pointing at `data:` URLs and at documents that can carry script in some rendering paths, which is real but small. `object-src 'none'` remains part of every strict CSP recipe and it costs nothing, so I am keeping the category rather than dropping it: it is defense-in-depth and it is scored that way.

**Frame Embedding (0.15).** Clickjacking is unglamorous, well understood, and still works. The thing that keeps this weight up is how frequently it is missed by accident: a site sets a tight `default-src` and assumes it is covered, and `frame-ancestors` does not fall back to `default-src`, so it is not covered at all.

**Form Actions (0.15).** Without `form-action`, an HTML injection that falls short of script execution can still repoint a login form at an attacker's endpoint. This is the directive that matters most exactly when your script controls held the line (i.e. the attacker got markup but not JavaScript), which is why it keeps a full 0.15 even though it looks minor next to XSS.

**Base URI (0.10).** `base-uri` stops an injected `<base>` tag from redirecting every relative URL on the page, including script sources. The risk needs a pre-existing HTML injection primitive, so on its own it is conditional. There is an open question buried in this weight that I would like to make clear: `base-uri` matters *most* precisely when you are using nonces, because a `<base>` injection can retarget a nonced relative script source at an attacker host (CSP3 §7.3). A flat 0.10 cannot express "this is cheap insurance normally and load-bearing under `'strict-dynamic'`." A conditional weight is a candidate for 0.3.

**Style Injection (0.10).** CSS injection leaks data through attribute selectors and timing, and it redresses UI convincingly. It is a genuine attack channel and it is also a slower, noisier, more constrained one than script execution, which is what the 0.10 is expressing.

**Frame Content (0.05).** New in 0.2. An injected iframe is the cheapest phishing overlay there is: a lookalike login form sitting inside the page the user already trusts, at the URL they already checked, under the padlock they already looked at. It needs no script execution and no compromised host, only an HTML injection primitive, and where `data:` is an allowed source the iframe carries its own document and needs no external host at all. It gets 0.05 and no more because of containment: the injected frame is cross-origin from the page around it, so it cannot read the parent DOM, touch the session, or exfiltrate anything the user does not type into it by hand. I will say plainly that 0.1 had this pair backwards. It gave `object-src` a category worth 0.15 for a plugin ecosystem that has been dead for years, and it gave `frame-src` nothing at all for an attack that works today. 0.2 fixes that.

> **What is not scored in 0.2.** The unscored directives are `connect-src`, `img-src`, `media-src`, `worker-src` and `manifest-src`. `connect-src` only starts to matter once an attacker already has script execution. `img-src`, `media-src` and `manifest-src` are hygiene. They are worth setting and the risk they carry is small enough that giving each one a weight would mostly add noise. `worker-src` is a real surface but a small one, and its chain (`worker-src` -> `child-src` -> `script-src` -> `default-src`) means a strict script policy usually covers it without anyone having to think about it. So in short, I didn't add the above in because I think they would needlessly complicate the scoring model. That could change as new attacks evolve, in which case we would rev the `model_version` (Section 8), and re-weight the directives.

---

## 5. Resolving the Policy Before You Score It

This section is Layer 1, and it is where most of the work is. Before any rubric runs, you have to turn "whatever arrived in the response headers" into one effective source list per category. Nearly every rule below is either new in 0.2 or a correction of something 0.1 got wrong, and several of them are places where a straightforward implementation gets the opposite of the spec's answer.

**Rule 1. Only enforced policies are scored.** `Content-Security-Policy-Report-Only` enforces nothing; it reports. It is partitioned out before scoring and reported as a flag (`report_only_present`), never merged into the enforced policy. A site running a beautiful strict policy in report-only mode and nothing in enforcement mode scores exactly the same as a site with no CSP, because that is exactly the protection it has.

**Rule 2. Multiple enforced policies are scored independently, then minimized per category.** Multiple `Content-Security-Policy` headers, or a comma-separated policy list inside one header value, produce multiple policies. CSP3 §8.1 says each is enforced independently and content must satisfy all of them, so the effective restriction is the strictest one. Score each policy on its own, then take the **per-category minimum** across policies. In 0.1 I said to use "the most restrictive value per directive," which sounds fine until you try to implement it: there is no defined way to intersect `script-src 'self' https://a.example` with `script-src 'nonce-...' 'strict-dynamic'`. Minimizing the *scores* is defined, and it is the closest honest approximation.

**Order of operations:** minimize first, then finish. Take the per-category minimum across policies, and apply the Section 7 modifiers, the Trusted Types adjustment and the Section 8 script cap once, afterwards, to the minimized values. Scoring each policy end to end and then minimizing the finished numbers is a different calculation, and it is not the one this document means.

**Rule 3. Within one policy, the first occurrence of a directive name wins.** If a policy contains `script-src 'self'; script-src *`, the effective value is `'self'` and the second one is ignored (CSP3 §2.2.1). This one matters because the obvious implementation gets it backwards: parse the policy into a dictionary with `directives[name] = value` and the *last* occurrence silently wins. That is also the basis of policy injection attacks, where an attacker who controls part of a reflected header appends a directive hoping to relax it. Under the spec they cannot relax an already-present directive, and the scorer needs to agree with the spec. (The PortSwigger policy injection technique works around this by adding a directive name that is *not* already present, e.g. `script-src-elem`, which is exactly why rule 5 resolves the `-elem` and `-attr` chains instead of stopping at `script-src`.)

**Rule 4. Keyword matching is on whole quoted tokens, never substrings.** `'wasm-unsafe-eval'` contains the string `unsafe-eval` and is a completely different, much narrower keyword. A substring search penalizes it as though it were the real thing. Tokenize the source list on whitespace and compare whole tokens.

**Rule 5. Use the spec's real fallback chains.** "Directive, else `default-src`" is not what CSP3 says. The chains that matter here:

| Category | Chain |
|---|---|
| Script, element context | `script-src-elem` -> `script-src` -> `default-src` |
| Script, attribute context | `script-src-attr` -> `script-src` -> `default-src` |
| Style, element context | `style-src-elem` -> `style-src` -> `default-src` |
| Style, attribute context | `style-src-attr` -> `style-src` -> `default-src` |
| Object / Plugin | `object-src` -> `default-src` |
| Frame Content | `frame-src` -> `child-src` -> `default-src` |
| Frame Embedding | `frame-ancestors`, no fallback |
| Form Actions | `form-action`, no fallback |
| Base URI | `base-uri`, no fallback |

Script Execution is scored as the **worse (lower) of the two resolved values**, element and attribute, and Style Injection likewise. The attribute context usually resolves to the same list as the element context, so most of the time this changes nothing; it exists for the policy that sets `script-src-elem 'nonce-...' 'strict-dynamic'` and leaves `script-src-attr` inheriting `'unsafe-inline'` from `default-src`, where inline event handlers still fire and the policy should not get full credit.

The three no-fallback directives deserve their own sentence, because this is the single most common CSP misunderstanding I run into on tests: a strict `default-src` does not give you clickjacking protection, form hijacking protection, or `<base>` protection. Those three have to be written out explicitly or they are simply unset.

**Rule 6. The `sandbox` directive is a precondition.** An enforced `sandbox` directive without `allow-scripts` means no script runs on that document at all, full stop, and Script, Object and Style are **raised to at least 0.98**, whatever the source lists say. Without `allow-forms`, Form Actions is raised to at least 0.98. (I stopped short of 1.00 because sandbox is coarse enough that people get it wrong.)

A floor and not an assignment, because an assignment would overwrite a category that has already earned more. `object-src 'none'` is worth 1.00 and it appears in every strict CSP recipe; `sandbox` only adds protection on top of it, so a rule that wrote 0.98 over that 1.00 would mean hardening a page lowered its score. That is the same inversion the origin-count tables in Section 6.3 are shaped to avoid, and it comes from the same place: a rule that sets a value without asking what was there. Set the `sandboxed` flag. Under 0.1's rubrics a fully sandboxed page with no other directives landed on that scale's worst possible result, which is about as wrong as this model can be.

Frame Content is deliberately not elevated by this rule. Sandbox flags propagate into nested browsing contexts, so an injected iframe inherits the restriction -- but it still *renders*. The lookalike login overlay that Section 6.7 is about is still drawn on the page, and whether the user's keystrokes reach anyone depends on `allow-forms`. That is a partial mitigation of a partly-visual attack, and picking a single precondition value for it would claim more precision than I have. Flagged as an open question for 0.3.

**Rule 7. The `'strict-dynamic'` keyword is a precondition, applied before scoring.** If the effective script directive contains `'strict-dynamic'` **and** a valid nonce or hash, then all host-source, scheme-source, `'self'` and `'unsafe-inline'` tokens are discarded from the list before any rubric row is considered (CSP3 §6.7.1.1 and §8.2). Browsers ignore them, so the scorer must too. This is not a hypothetical: the backward-compatible strict policy that the CSP3 spec and Google's own strict CSP guidance both recommend looks like `'nonce-...' 'strict-dynamic' 'unsafe-inline' https: http:`, and 0.1 scored it **0.95** because the `https:` token matched the wildcard row on the way down the first-match tree. The recommended policy scored almost as badly as no policy. That was the bug that convinced me 0.1 needed a structural fix rather than a tuning pass.

**Rule 8. Nonce validity has a minimum, and there is a cheap check for static nonces.** A nonce counts as a nonce only if its base64 payload decodes to at least 16 bytes, per the CSP3 §7.1 SHOULD of at least 128 bits of entropy. Anything shorter is treated as no nonce at all and flagged `weak_nonce`. (0.1's worked example used `'nonce-abc123'`, which under 0.2 would be flagged. I am not proud of that.) Additionally, in `--url` mode the CLI fetches the page twice: if the nonce value is identical across both responses then it is effectively a password that ships with every page, so it is treated as no nonce and flagged `static_nonce`. Two fetches is not a rigorous randomness test and it will not catch a nonce that cycles through a small pool, but it catches the hardcoded case, which is the common one.

**Rule 9. Meta-delivered CSP is not parsed in 0.2.** Policies delivered by `<meta http-equiv>` require fetching and parsing the document body, which puts this outside header-level analysis. If a future version does parse them, it must discard `frame-ancestors`, `sandbox` and `report-uri` from meta policies, because browsers ignore those in meta delivery (CSP3 §3.3), and crediting them would inflate the score for protections that are not actually in effect.

**Rule 10. An `'unsafe-inline'` token is neutralized by a valid nonce or hash in the same directive.** This is unchanged from 0.1 in substance, but it now depends on rule 8: the neutralization only happens if the nonce is actually valid. `'unsafe-inline'` alongside a 4-byte nonce is active `'unsafe-inline'`.

### Terminology

- **Effective source list.** What is left for a category after rules 1 through 10 have run.
- **Absent.** No effective directive covers the category, either because nothing in the chain is present or because the category has no fallback and its directive was not written.
- **Active `'unsafe-inline'`.** `'unsafe-inline'` present and not neutralized by a valid nonce or hash.
- **Valid nonce or hash.** A `'nonce-...'` whose payload decodes to at least 16 bytes and is not known-static, or a `'sha256-'` / `'sha384-'` / `'sha512-'` source.
- **Host source.** An origin like `https://cdn.example.com`. **Scheme source** means a bare `https:`, `http:`, `data:` or `blob:`.

---

## 6. The Rubrics

Every category returns a protection value `p` in [0.00, 1.00], where 1.00 means the category is fully closed and 0.00 means it is fully exposed. All rubrics are evaluated against the effective source list from Section 5.

One rule applies to all seven tables: **these are not first-match decision trees.** You pick the row that describes the trust model of the source list, and where more than one row genuinely describes it, you take the **lowest-scoring** row. This matters for lists like `'self' 'unsafe-inline' https:`, where both the scheme-source row and the active-`'unsafe-inline'` row apply and the answer is the lower of the two.

That rule only produces an answer if *some* row applies. An earlier draft of this version had four tables where a legal source list matched no row at all, which is 0.1's unreachable-row failure wearing a different hat: either way the implementer is left to pick. Two supporting rules close it:

**Every table below is exhaustive.** For each category, any effective source list matches at least one row. Where a table distinguishes counts of external origins, the rows cover 0, 1, 2 and 3-or-more, so there is no gap to fall into. An implementation that finds no applicable row has found a bug in this document, and should say so loudly rather than picking a value.

**The `'none'` row is exclusive.** Exhaustiveness cuts both ways: `'none'` and an empty source list also have zero external origins, so on a count-keyed table they would match the zero-origin row as well, and the lowest-row rule would then quietly prefer 0.92 over the 1.00 that `'none'` has earned. When the `'none'` row applies, no other row does.

**A keyword-only list is an empty list.** A source list containing no source expressions -- only keywords the rubric handles as deductions -- is scored as an empty source list. `script-src 'unsafe-eval'` blocks every script load and then permits `eval()` on what never loaded, so it scores as `'none'` (1.00) with the deduction applied (0.85). Reading it as "undefined" or as a bare `'unsafe-eval'` penalty gets a very restrictive directive badly wrong.

### 6.1 Script Execution

The script rubric is a **base value plus deductions**, which is the other structural change in 0.2. The 0.1 version was a first-match tree, and it had two problems I could not tune my way out of. First, it had no row for `script-src 'none'`, so the correct answer for the most restrictive possible value was undefined and fell through to whatever the implementer felt like. Second, because the tree matched on one condition and stopped, `'strict-dynamic' 'nonce-...' 'unsafe-eval'` matched the "`'unsafe-eval'` only" row and landed at **0.55**, scoring a strict nonce policy with one legacy `eval()` dependency worse than a plain `'self'` allowlist. Separating the trust model from the specific relaxations fixes both.

**Step 1.** Pick the one base-value row that describes the trust model of the effective source list, after rules 6 through 8 have been applied. If two rows describe it (e.g. `'self' 'unsafe-inline' https:` is both a scheme-source list and an active-`'unsafe-inline'` list), take the lower one. IMPORTANT: an implementation that walks the table top to bottom and stops at the first hit will get this wrong, and Example C shows exactly where.

The four tokens Step 2 handles as deductions -- `'unsafe-eval'`, `'unsafe-hashes'`, `'wasm-unsafe-eval'` and `blob:` -- take no part in choosing the base row. Strip them first, so nothing is charged for twice. This is why `blob:` does not appear in the scheme-source row, and it settles `script-src blob:`: stripping `blob:` leaves an empty list, so the base is 1.00 and the deduction brings it to 0.90. That is the right answer. Minting a blob URL takes script that is already running, so a directive allowing only `blob:` loads nothing an attacker can reach without already having won.

| Effective source list | Base `p` |
|---|---|
| `'none'`, or an empty source list | 1.00 |
| `'strict-dynamic'` with a valid nonce or hash | 0.90 |
| Valid nonce or hash, no host or scheme sources, no `'strict-dynamic'` | 0.85 |
| `'self'` only (no external hosts, no nonce) | 0.70 |
| `'strict-dynamic'` with **no** valid nonce or hash | 0.65 |
| Valid nonce or hash **plus** 1-2 external host origins, no `'strict-dynamic'` | 0.60 |
| Valid nonce or hash **plus** 3+ external host origins, no `'strict-dynamic'` | 0.50 |
| External host allowlist, 1-2 origins, no nonce (with or without `'self'`) | 0.50 |
| External host allowlist, 3+ origins, no nonce (with or without `'self'`) | 0.40 |
| Wildcard `*`, a scheme source (`https:`, `http:`), or `data:`, and not discarded by rule 7 | 0.10 |
| Active `'unsafe-inline'` (no valid nonce or hash) | 0.05 |
| Directive absent | 0.00 |

A couple of those rows need defending.

`'strict-dynamic'` without a nonce or hash lands at 0.65, which is better than an allowlist. In 0.1 I described bare `'strict-dynamic'` as "meaningless," and that is not right: with no nonce and no hash there is nothing to propagate trust from, so every parser-inserted script is blocked, which is extremely restrictive. It also breaks most real sites, and it matched no row at all in 0.1's tree. 0.65 says "this is genuinely restrictive and you have almost certainly misconfigured it."

The nonce-plus-hosts rows sit exactly 0.10 above their no-nonce equivalents, and that small gap is on purpose. Adding a nonce to an allowlist without adding `'strict-dynamic'` does not remove the allowlist; the CDN is still trusted and still the weak link. Weichselbaum et al. found that roughly three quarters of distinct policies with script allowlists were bypassable ("CSP Is Dead, Long Live CSP!", CCS 2016), and bolting a nonce onto one of those policies does not make the allowlisted host stop hosting the gadget. The nonce adds a safe path and closes nothing.

**Step 2.** Subtract each of the following deductions that applies, then clamp the total at 0.00.

| Token present in the effective list | Deduction |
|---|---|
| `'unsafe-eval'` | -0.15 |
| `'unsafe-hashes'` | -0.10 |
| `'wasm-unsafe-eval'` | -0.05 |
| `blob:` | -0.10 |

`blob:` gets a deduction rather than the 0.10 scheme-source row that `data:` gets, because the two are not equivalent. Minting a blob URL requires script that is already running, so `blob:` in `script-src` is a gadget amplifier that helps an attacker who already has execution. A `data:` URL can be written straight into injected markup, which makes it an injection primitive. Same family, different severity.

**Step 3.** The Trusted Types modifier comes last. It closes a share of whatever exposure the directive still has:

```
p_script = p + 0.25 * (1 - p)     # require-trusted-types-for 'script'
p_script = p + 0.35 * (1 - p)     # ...and a trusted-types allowlist directive as well
```

So a script directive already sitting at 0.85 goes to 0.8875 with Trusted Types, and one sitting at 0.05 goes to 0.2875. The better your directive already is, the less there is left for Trusted Types to close, which is the behavior I want. This is applied to `p_script` before the cap in Section 8.

Trusted Types was a rubric row worth full credit in 0.1, and that was too generous by a wide margin. It only covers DOM XSS sinks (`innerHTML`, `eval`, and friends). It does nothing about reflected or stored XSS that arrives in the server's response, which is still the bulk of what I find. Closing 25% to 35% of the remaining gap says what it deserves: a real, meaningful control that shuts one category of sink and leaves others open. The exact percentages are judgment, and I am open to argument on them.

### 6.2 Object / Plugin

Rows unchanged from 0.1 in substance; only the category weight moved and the direction flipped.

| Effective source list | `p` |
|---|---|
| `'none'`, or an empty source list | 1.00 |
| `'self'` only (no external origins) | 0.85 |
| External host allowlist | 0.65 |
| `data:` | 0.25 |
| Wildcard `*` or a scheme source | 0.10 |
| Directive absent | 0.00 |

### 6.3 Frame Embedding

Evaluate `frame-ancestors`. No fallback.

| Effective source list | `p` |
|---|---|
| `'none'`, or an empty source list | 1.00 |
| No external origins | 0.92 |
| Exactly 1 external origin (with or without `'self'`) | 0.80 |
| Exactly 2 external origins (with or without `'self'`) | 0.70 |
| 3 or more external origins (with or without `'self'`) | 0.50 |
| `*`, or a scheme source | 0.10 |
| Directive absent | 0.00 |

**Count the external origins; `'self'` is not one of them.** Worth spelling out, because the same shape repeats in Sections 6.4 and 6.7. 0.1 had a row reading "`'self'` (possibly with one trusted origin)" scored at 0.10, sitting *below* the 1-2 entries row in a first-match tree, which made it unreachable for anything but bare `'self'`. The obvious repair is to key the rows on whether `'self'` is present, and that breaks two ways: `frame-ancestors 'self' https://a.example https://b.example` then matches no row at all, and `frame-ancestors https://partner.example` scores *below* `frame-ancestors 'self' https://partner.example`, which allows strictly more. Adding an origin would raise the score.

Counting external origins and ignoring `'self'` avoids both. `'self'` is your own origin; it is never the party that framed you, and whether you also list it changes nothing about who else can. Each additional party you let frame the page does.

### 6.4 Form Actions

Evaluate `form-action`. No fallback. Same shape as frame embedding, because the structure of the risk is the same: every additional origin is another place your credentials can legally be posted.

| Effective source list | `p` |
|---|---|
| `'none'`, or an empty source list | 1.00 |
| No external origins | 0.92 |
| Exactly 1 external origin (with or without `'self'`) | 0.80 |
| Exactly 2 external origins (with or without `'self'`) | 0.70 |
| 3 or more external origins (with or without `'self'`) | 0.50 |
| `*`, or a scheme source | 0.10 |
| Directive absent | 0.00 |

### 6.5 Base URI

Evaluate `base-uri`. No fallback.

| Effective source list | `p` |
|---|---|
| `'none'`, or an empty source list | 1.00 |
| No external origins | 0.92 |
| 1 or more external origins (with or without `'self'`) | 0.60 |
| `*`, or a scheme source | 0.10 |
| Directive absent | 0.00 |

There is almost never a legitimate reason to allow an external origin here, which is why the drop from 0.92 to 0.60 is so steep, and why this table does not bother counting past one. A scheme source belongs with `*` here, because a `<base>` tag pointing anywhere on the HTTPS internet is the whole attack. See the open question about conditional weighting in Section 4.

### 6.6 Style Injection

Evaluate the style chain from rule 5, worse of element and attribute contexts. The same lowest-row rule applies here: `'unsafe-inline'` next to `https:` is scored as the scheme source (0.10), which is the lower of the two.

| Effective source list | `p` |
|---|---|
| `'none'`, or an empty source list | 1.00 |
| Valid nonce or hash, no host or scheme sources, no active `'unsafe-inline'` | 0.95 |
| `'self'` only (no nonce or hash, no external origins) | 0.90 |
| External host allowlist, no active `'unsafe-inline'` | 0.65 |
| Active `'unsafe-inline'` | 0.35 |
| Wildcard `*` or a scheme source | 0.10 |
| Directive absent | 0.00 |

Deduction: `'unsafe-hashes'` subtracts 0.05, clamped at 0.00.

Worth noting, since it trips people up: `style-src 'self' 'unsafe-inline'` is extremely common, because a lot of frameworks inject inline styles and nobody wants to hash them. It scores 0.35, which at a weight of 0.10 costs you 0.65 points against the 1.00 the category could have contributed. That is the model saying this is a real weakness and it is not the one to fix first.

### 6.7 Frame Content

Evaluate `frame-src`, falling back to `child-src` and then `default-src` per rule 5. This category is new in 0.2.

| Effective source list | `p` |
|---|---|
| `'none'`, or an empty source list | 1.00 |
| No external origins | 0.90 |
| Exactly 1 external origin (with or without `'self'`) | 0.80 |
| Exactly 2 external origins (with or without `'self'`) | 0.70 |
| 3 or more external origins (with or without `'self'`) | 0.50 |
| `data:` | 0.25 |
| Wildcard `*` or a scheme source | 0.10 |
| Directive absent | 0.00 |

The shape follows the frame embedding and form action tables, because the risk grows the same way: every origin you allow is another party whose content can be made to appear inside your page. `data:` gets its own row for the same reason it gets one under `object-src`. An injected `<iframe src="data:text/html,...">` carries its own document in the attribute, so the attacker needs no host, no upload, and nothing on the network that you could have noticed.

`'self'` sits at 0.90 here instead of the 0.92 used for frame embedding and form actions, which is a small deliberate difference: a same-origin iframe is a normal, useful thing that many applications genuinely need, and it is also a place where an open redirect or a user-content page on your own origin becomes a frame you did not intend.

---

## 7. Other Headers as Modifiers

A couple of response headers overlap with CSP directives. A modifier assigns a protection value to one specific category, and since the gate below means the category is sitting at 0.00 whenever a modifier can apply, an assignment is all that is needed. (0.1 gave two conflicting definitions for this, a cap on maximum contribution in prose and a proportional reduction in the formula. Both are gone.)

| Header | Value | Category | Sets `p` to |
|---|---|---|---|
| `X-Frame-Options` | `DENY` | Frame Embedding | 0.80 |
| `X-Frame-Options` | `SAMEORIGIN` | Frame Embedding | 0.60 |

### X-Frame-Options

**The gate condition is the important part.** `X-Frame-Options` is applied **only when no enforced policy contains a `frame-ancestors` directive at all.** In 0.1 the gate keyed off the category's own score instead, which is a different condition. That older gate would have credited a site running `frame-ancestors *` plus `X-Frame-Options: DENY`, and browsers ignore `X-Frame-Options` entirely when `frame-ancestors` is present (CSP3 §6.4.2.2), so the site's actual behavior is wide-open framing. The old rule would have rewarded it. If `frame-ancestors` is present in an enforced policy, in any form, the modifier does not apply.

**The values are a judgment call, and a big change.** 0.1 allowed `DENY` to recover only 40% of what the missing directive cost, and justified that partly with "policies that rely solely on `X-Frame-Options` represent an outdated configuration." That is a statement about how current the configuration is, and this score is supposed to measure protection. For the actual attack, clickjacking, `X-Frame-Options: DENY` is functionally equivalent to `frame-ancestors 'none'` in every browser a real user is running. So the credit should be large, and 0.2 gives it 0.80 of the 1.00 that `frame-ancestors 'none'` would earn.

The 0.20 I am holding back is for deployment fragility: `X-Frame-Options` cannot be delivered by `<meta>` (so a page relying on it loses it in any context where headers are stripped or rewritten), and `SAMEORIGIN` ancestor-chain checking varied historically between browsers, with some checking only the top-level document rather than every ancestor. `SAMEORIGIN` gets 0.60 for that reason. I want to flag clearly that 0.80 and 0.60 are my judgment and someone will reasonably argue for 0.90 and 0.70, or for 0.60 and 0.40.

### What happened to the Permissions-Policy modifier

It is deleted. In 0.1, `Permissions-Policy` applied a 5% reduction to Style Injection, and I cannot reconstruct a defensible reason for that pairing: `Permissions-Policy` governs access to browser APIs like camera and geolocation, and has nothing to do with CSS injection. Even taking the pairing at face value, the maximum possible effect was 0.05 x 0.10 x 9 under 0.1's scale, which is 0.045 points, comfortably below the one-decimal reporting precision. It could never change a displayed score. Presence is now reported as a flag and nothing more.

### Why not more headers

`X-Content-Type-Options: nosniff`, `Strict-Transport-Security`, and `Referrer-Policy` are all worth having and none of them change the answer to "how much client-side attack surface does this policy leave open." Folding them in would dilute the CSP-specific signal and turn this into a worse version of a general header grader, which already exists and which you should also run.

---

## 8. How the Number Gets Made

**Step 1.** Resolve the seven effective source lists per Section 5.

**Step 2.** Apply the rubrics from Section 6 to get protection values `p_i` in [0.00, 1.00].

**Step 3.** Apply the Trusted Types modifier to `p_script`, and the `X-Frame-Options` modifier to `p_frame` if its gate condition is met.

```
p_script = max(base - deductions, 0.00)
p_script = p_script + tt_share * (1 - p_script)    # tt_share is 0.25 or 0.35
p_frame  = xfo_value                                # only if no enforced frame-ancestors
```

**Step 4.** Compute the weighted sum.

```
weighted = SUM( w_i * p_i )     for the seven categories, SUM(w_i) = 1.00
```

**Step 5.** Apply the script cap and scale.

```
csp_score = 10.0 * min(weighted, p_script)
```

**Step 6.** Round to one decimal place. The result runs from 0.0 to 10.0.

### The cap, in plain English

Your score can never be higher than your `script-src`. That is the whole rule, and it is the most important change in 0.2. Section 4 of 0.1 said, correctly, that open script execution makes every other directive academic, and then the formula went ahead and averaged it away: a policy with no `script-src` at all but perfect values everywhere else came out in the comfortable middle of 0.1's range and got a reassuring label. A site where an attacker can run arbitrary JavaScript in your users' sessions has not earned a middling result. Under the cap that policy scores **0.0**, because that is what its script directive is worth and nothing else can lift it.

Two consequences worth stating out loud. Once the cap is what binds, improvements to the other six categories stop moving the number, which is intentional: if your script directive is absent, tightening `base-uri` is not the work. When the weighted sum is the lower of the two, it does the talking and all seven categories matter normally. Example B in the next section is a policy that has fixed its script problem completely and still lands in the Weak band, which is exactly the behavior I wanted.

### Bands

| Score | Rating | What it means |
|---|---|---|
| 8.5 - 10.0 | Strong | Restrictive policy; little left to tighten. |
| 6.5 - 8.4 | Moderate | Real protection with a gap or two worth closing. |
| 4.0 - 6.4 | Weak | Several attack surfaces left open. |
| 1.5 - 3.9 | Poor | Little practical protection; probably a checkbox policy. |
| 0.0 - 1.4 | Negligible | No CSP, or one that may as well not be there. |

### Output contract

JSON output carries `csp_score`, always carries `rating` even when a caller only asked for the number, and always carries `model_version`. Higher is better, on a 0.0 to 10.0 scale, and 0.0 covers both "no CSP" and "a policy that stops nothing." How a tool chooses to show the difference between those two (a dash, the word "none", a separate flag) is the tool's business and outside this calculator.

`model_version` is not bookkeeping: the scores in this document will change between versions, so a CI gate written as `--min-score 7.5` has to be pinned to a model version or your build breaks on an upgrade for reasons that have nothing to do with your code. The CLI requires the pin.

---

## 9. Worked Examples

All four are computed by hand below. If you get a different number, that is a bug in this document and I would like to hear about it.

### Example A: a full nonce-based policy

```
Content-Security-Policy:
  script-src 'nonce-VOSYT20SImp81YScafJexg==' 'strict-dynamic';
  object-src 'none';
  style-src 'self';
  frame-src 'self';
  frame-ancestors 'self';
  form-action 'self';
  base-uri 'none'
```

| Category | Effective value | Rubric row | p_i | w_i | w_i x p_i |
|---|---|---|---|---|---|
| Script Execution | nonce + `'strict-dynamic'` | strict-dynamic with valid nonce | 0.90 | 0.40 | 0.360 |
| Object / Plugin | `'none'` | `'none'` | 1.00 | 0.05 | 0.050 |
| Frame Embedding | `'self'` | `'self'` only | 0.92 | 0.15 | 0.138 |
| Form Actions | `'self'` | `'self'` only | 0.92 | 0.15 | 0.138 |
| Base URI | `'none'` | `'none'` | 1.00 | 0.10 | 0.100 |
| Style Injection | `'self'` | `'self'` only | 0.90 | 0.10 | 0.090 |
| Frame Content | `'self'` | `'self'` only | 0.90 | 0.05 | 0.045 |
| **weighted** | | | | | **0.921** |

```
csp_score = 10.0 * min(0.921, 0.90)
          = 10.0 * 0.90
          = 9.0
```

**9.0 / 10.0 (Strong).** Note which number won the `min()`: the weighted sum is 0.921, but the script value of 0.90 is lower, so the cap binds and the script directive sets the score single-handedly. That is the intended reading of this policy. Everything else in it is better than the script directive, so the script directive is the answer. The nonce here is a real 128-bit value, which matters under rule 8: swap in `'nonce-abc123'` and the policy is scored as having no nonce at all, which knocks out the `'strict-dynamic'` precondition and puts you somewhere entirely different.

### Example B: Google's recommended backward-compatible strict CSP

```
Content-Security-Policy:
  script-src 'nonce-AAPYI1KqZa5DErkp38/t6A==' 'strict-dynamic' 'unsafe-inline' https: http:;
  object-src 'none';
  base-uri 'none'
```

Rule 7 fires first: `'strict-dynamic'` plus a valid nonce discards `'unsafe-inline'`, `https:` and `http:` before scoring, leaving `'nonce-...' 'strict-dynamic'`.

| Category | Effective value | Rubric row | p_i | w_i | w_i x p_i |
|---|---|---|---|---|---|
| Script Execution | nonce + `'strict-dynamic'` (rest discarded) | strict-dynamic with valid nonce | 0.90 | 0.40 | 0.360 |
| Object / Plugin | `'none'` | `'none'` | 1.00 | 0.05 | 0.050 |
| Frame Embedding | absent | absent | 0.00 | 0.15 | 0.000 |
| Form Actions | absent | absent | 0.00 | 0.15 | 0.000 |
| Base URI | `'none'` | `'none'` | 1.00 | 0.10 | 0.100 |
| Style Injection | absent | absent | 0.00 | 0.10 | 0.000 |
| Frame Content | absent (no `default-src` to inherit) | absent | 0.00 | 0.05 | 0.000 |
| **weighted** | | | | | **0.510** |

```
csp_score = 10.0 * min(0.510, 0.90)
          = 10.0 * 0.510
          = 5.1
```

**5.1 / 10.0 (Weak).** This is the example I would point at first. The policy is the spec's own recommended recipe for strict CSP with backward compatibility, and it has genuinely solved the script problem: 0.90, the same value as Example A, because rule 7 correctly throws away the compatibility tokens. Version 0.1 scored this exact policy one rung above "no policy at all" on script, which was flatly wrong.

But solving XSS is not the whole job, and this policy does nothing else. No `frame-ancestors`, so it can be framed. No `form-action`, so a markup injection can repoint the login form. No `style-src`, so CSS injection is unconstrained. No `frame-src` and no `default-src` for it to inherit, so an injected iframe can pull in anything it likes. Four categories sitting at 0.00 is what holds a policy with an excellent script directive down in the Weak band, and I think that is the right answer: the strict-CSP recipe is the hard part, it is done, and there are four one-line directives left to add that would take this to 9.0 (weighted 0.921, capped by the script value of 0.90).

### Example C: the checkbox policy

```
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval' https:
```

Every category with a fallback resolves through `default-src`. There is no nonce, so `'unsafe-inline'` is active. For script, both the scheme-source row (0.10) and the active-`'unsafe-inline'` row (0.05) describe the list, so the lower one wins, then `'unsafe-eval'` takes off 0.15 and the total clamps at 0.00. Style works the same way: `'unsafe-inline'` is 0.35 and the `https:` scheme source is 0.10, so 0.10.

| Category | Effective value | Rubric row | p_i | w_i | w_i x p_i |
|---|---|---|---|---|---|
| Script Execution | via `default-src` | active `'unsafe-inline'` 0.05, `-0.15` eval, clamped | 0.00 | 0.40 | 0.000 |
| Object / Plugin | via `default-src` | scheme source `https:` | 0.10 | 0.05 | 0.005 |
| Frame Embedding | absent (no fallback) | absent | 0.00 | 0.15 | 0.000 |
| Form Actions | absent (no fallback) | absent | 0.00 | 0.15 | 0.000 |
| Base URI | absent (no fallback) | absent | 0.00 | 0.10 | 0.000 |
| Style Injection | via `default-src` | scheme source `https:` | 0.10 | 0.10 | 0.010 |
| Frame Content | via `default-src` | scheme source `https:` | 0.10 | 0.05 | 0.005 |
| **weighted** | | | | | **0.020** |

```
csp_score = 10.0 * min(0.020, 0.00)
          = 10.0 * 0.00
          = 0.0
```

**0.0 / 10.0 (Negligible).** This is the policy from the top of the document, and it is the one I find most often in the wild. It ties with having no CSP header whatsoever, which is the honest answer: with `'unsafe-inline'` and `'unsafe-eval'` active and `https:` as a source, there is no injected script this policy stops. Someone will object that surely a present-but-useless policy should rank slightly above nothing at all, on the theory that partial credit encourages progress. I do not agree. There is no attack it prevents, so there is no credit to give, and a scoring system that awards points for a header that does nothing is how we got the pass/fail scanners in the first place.

### Example D: no CSP, with X-Frame-Options

```
(no Content-Security-Policy header)
X-Frame-Options: DENY
```

No enforced policy means no `frame-ancestors` anywhere, so the modifier gate in Section 7 opens and Frame Embedding is set to 0.80.

| Category | Effective value | Rubric row | p_i (raw) | Modifier | p_i | w_i | w_i x p_i |
|---|---|---|---|---|---|---|---|
| Script Execution | absent | absent | 0.00 | none | 0.00 | 0.40 | 0.000 |
| Object / Plugin | absent | absent | 0.00 | none | 0.00 | 0.05 | 0.000 |
| Frame Embedding | absent | absent | 0.00 | XFO DENY, set to 0.80 | 0.80 | 0.15 | 0.120 |
| Form Actions | absent | absent | 0.00 | none | 0.00 | 0.15 | 0.000 |
| Base URI | absent | absent | 0.00 | none | 0.00 | 0.10 | 0.000 |
| Style Injection | absent | absent | 0.00 | none | 0.00 | 0.10 | 0.000 |
| Frame Content | absent | absent | 0.00 | none | 0.00 | 0.05 | 0.000 |
| **weighted** | | | | | | | **0.120** |

```
csp_score = 10.0 * min(0.120, 0.00)
          = 10.0 * 0.00
          = 0.0
```

**0.0 / 10.0 (Negligible).** The `X-Frame-Options` header does real work here and you can see it doing that work: Frame Embedding shows 0.80 instead of 0.00 in the category breakdown, the modifier is listed in the output, and the weighted sum comes to 0.120 instead of 0.000. And the score does not move, because the script cap is sitting at 0.00 and no amount of clickjacking protection changes the fact that there is no CSP. This is the cap behaving correctly, and the credit for the header shows up in the breakdown, which is where it belongs.

---

## 10. Leftover Edge Cases

Most of what was in this section in 0.1 became actual resolution rules in Section 5, which is where it belonged. What is left:

**No headers at all.** Every category is absent, every raw value is 0.00, and the score is 0.0. With a modifier header present the weighted sum rises a little, but the script cap keeps the score pinned at 0.0, as in Example D.

**Malformed or unparseable policies.** A directive name the parser does not recognize is ignored (CSP3 requires browsers to ignore unknown directives, so the scorer does too) and reported in a flag. A policy that is entirely unparseable is scored as absent, with a flag, on the grounds that a browser will not get anything useful out of it either.

**Scheme sources in general.** `https:` in `script-src` allows script from any HTTPS origin on the internet, which is a wildcard wearing a tie. It scores as one. `data:` is worse in practice than its row suggests, because a `data:` URL in `script-src` means injected markup can carry its own payload with no external fetch at all, and the only reason it does not score below `'unsafe-inline'` is that it still needs a tag to be injected.

**Report-only policies alongside enforced ones.** Scored per rule 1: only the enforced policy counts, and the report-only one is a flag. This is a common and good deployment pattern (test the tighter policy in report-only, then promote it), and it is worth being clear that the score will not move until the promotion happens.

---

## 11. Tooling

The reference implementation is not written yet. The intent is a Python library `csp_index` exposing a `compute_score()` call that takes the header string and a dict of other response headers, plus a CLI wrapping it:

```bash
csp-index --url https://example.com
csp-index --header "script-src 'nonce-VOSYT20SImp81YScafJexg==' 'strict-dynamic'"
csp-index --file headers.json
csp-index --url https://example.com --json --min-score 7.5 --model-version 0.2.0
```

JSON output carries `csp_score`, `rating`, `model_version`, the per-category breakdown with raw value, applied modifier and weight, the list of modifiers applied, and the flags from Section 5 (`report_only_present`, `sandboxed`, `weak_nonce`, `static_nonce`, and so on). The `--min-score` gate requires `--model-version` for the reason given in Section 8.

The library is designed to be callable from [csp-lab](https://github.com/JGillam/csp-lab) pipelines, so that a bulk CSP dataset can get a score column and the classification work in `docs/csp-component-classifications.md` can be cross-referenced against it. That is the main reason determinism is a hard requirement: rescoring 750,000+ policies has to produce the same answers on Tuesday that it produced on Monday.

Four uses I have in mind, roughly in order of how much I want them to exist: a CI gate that fails the build when a policy regresses below a pinned threshold, a reproducible number to put in a penetration test report next to the remediation guidance, bulk scoring for research on how CSP quality is actually trending, and developer tooling (an IDE plugin, a proxy extension) that shows the score while someone is editing the policy.

---

## 12. Limitations and Future Work

**Header-only analysis.** This scores a string. It does not know whether nonces are regenerated per request (beyond the two-fetch check in rule 8), whether the policy is served on every page or only the home page, or whether a service worker is rewriting things on the way out.

**No context sensitivity.** `form-action 'self'` scores 0.92 whether the site is a banking login or a recipe blog. Weighting risk by what the application actually does requires knowledge that is not in the header, and building it in would break determinism.

**Allowlist quality.** This is the biggest one. The rubric charges you for having an external host allowlist, but it cannot tell `script-src https://cdn.a-careful-partner.com` from `script-src https://a-cdn-that-hosts-user-uploads.example`, and in practice that difference is the whole ballgame. The Weichselbaum result mentioned in Section 6.1 is really a result about allowlist quality: roughly three quarters of distinct allowlist policies were bypassable, mostly through what the allowlist contained. Scoring this properly means maintaining a list of known-bypassable origins, which is a data maintenance problem, and it is the most valuable thing this project could add.

**Dynamic policies.** Per-request generation, `<meta>` overrides (rule 9), and service-worker-managed policies are all outside header-level static analysis.

### Candidates for 0.3

`connect-src`, for post-XSS exfiltration paths, if I can find a framing that survives the argument in Section 4. `worker-src`, which is a small but growing isolation-bypass surface. A conditional weight for `base-uri` that rises when nonces are in use, per the open question in Section 4. Allowlist quality scoring against a maintained list of known-bypassable CDN origins. And a credit for Subresource Integrity used alongside an allowlist, since SRI is the one thing that actually hardens a CDN allowlist.

### Calibration

Every weight, every rubric row, and every modifier percentage in this document is expert judgment. Mine, mostly, informed by what I see on tests and by the csp-lab dataset, but judgment all the same, and none of it has been validated against outcomes. What would make it better: correlation against known-exploited CSP configurations from public advisories, a serious look at whether the rubric rows rank real-world bypass difficulty in the right order, and enough people disagreeing with specific numbers in public that the numbers get defended or changed. If you have incident data that would help calibrate any of this, I would very much like to talk.

---

## 13. What Changed Since 0.1

Version 0.1 was a reasonable first pass that did not survive contact with the specification. Splitting the changes into two lists, because they deserve different amounts of argument.

### Fixes to spec contradictions and undefined behavior

1. `Content-Security-Policy-Report-Only` is now partitioned out and reported as a flag rather than being vaguely "treated as absent, though it may be noted separately" (rule 1).
2. Multiple enforced policies are scored independently with a per-category minimum, replacing 0.1's "use the most restrictive effective value per directive," which is not a defined operation on source lists (rule 2).
3. Duplicate directive names within one policy now resolve to the first occurrence, per CSP3 §2.2.1, which is the opposite of what a dictionary-based parser does by default (rule 3).
4. Keyword matching is specified as whole-token, so `'wasm-unsafe-eval'` is no longer penalized as `'unsafe-eval'` (rule 4).
5. Fallback chains now include `script-src-elem` / `script-src-attr` and `style-src-elem` / `style-src-attr`, scored as the worse of the two contexts, instead of 0.1's single "directive else `default-src`" step (rule 5).
6. An enforced `sandbox` without `allow-scripts` now raises Script, Object and Style to at least 0.98; under 0.1 a fully sandboxed page with no other directives landed on that scale's worst possible result (rule 6).
7. `'strict-dynamic'` with a valid nonce now discards host, scheme, `'self'` and `'unsafe-inline'` tokens before scoring, which fixes 0.1 scoring the spec's own recommended backward-compatible strict policy near the bottom of its script rubric because `https:` matched a wildcard row (rule 7).
8. The script rubric is a base value plus deductions instead of a first-match tree, which gives `script-src 'none'` a defined result (it had none) and stops `'strict-dynamic'` plus a nonce plus `'unsafe-eval'` from being scored as though the `eval()` were the only thing in the directive. The deduction tokens take no part in choosing the base row, so nothing is charged for twice (Section 6.1).
9. Nonces must decode to at least 16 bytes to count, and `--url` mode fetches twice to catch static nonces; 0.1 accepted any string after the `'nonce-'` prefix, including its own example (rule 8).
10. `'strict-dynamic'` without a nonce is now scored at 0.65 as a very restrictive misconfiguration, where 0.1 called it "meaningless" and gave it no matching row at all (Section 6.1).
11. The `frame-ancestors` `'self'` row, which was unreachable in 0.1's first-match tree because the 1-2 entries row sat above it, is gone; Frame Embedding, Form Actions and Frame Content are now keyed on the external origin count alone, with `'self'` not counted, which makes those tables exhaustive and stops a strictly more restrictive policy from scoring below a looser one (Sections 6.3, 6.4, 6.7).
12. `X-Frame-Options` now applies only when no enforced policy contains `frame-ancestors`, replacing a gate that would have credited `frame-ancestors *` plus `X-Frame-Options: DENY` (Section 7).
13. A modifier is now defined once, as an assignment of a protection value to the category, replacing 0.1's two conflicting definitions (a cap on maximum contribution in the prose, a proportional reduction in the formula) (Section 7).
14. The `Permissions-Policy` modifier is deleted, because it has no relationship to CSS injection and its maximum effect of 0.045 points on 0.1's scale could never change a displayed score (Section 7).
15. `require-trusted-types-for 'script'` closes a share of whatever exposure the script directive still has, instead of being a rubric row worth full credit, since it only covers DOM XSS sinks (Section 6.1).
16. `navigate-to`, which 0.1 listed as a no-fallback control and as a v2 scoring candidate, is removed from this document entirely, since it was struck from CSP3 and no browser implements it (Section 4).
17. The companion project is correctly named [csp-lab](https://github.com/JGillam/csp-lab); 0.1 called it "csp-analysis," which is not a repository that exists (Section 11).
18. Every rubric table is exhaustive: a keyword-only source list scores as an empty one, every `'none'` row covers the empty list, `base-uri` gained the scheme-source row the other tables already had, and rule 2 states its order of operations. 0.1's first-match trees left several legal source lists undefined, and "take the lowest applicable row" is only a rule if a row always applies (Sections 5 and 6).
19. The JSON field `index` is renamed `csp_score`, `rating` and `model_version` are always emitted, and the CI gate `--min-score` now requires a pinned model version (Section 8).
20. The claim that `script-src *; object-src *` is "arguably worse than no CSP" is dropped, since no defensible model can score it worse than absence; it is no better than no CSP, and the real harm is the false sense of security (Section 1).
21. Frame Content is added as a seventh category, scoring `frame-src` through its real chain of `frame-src` to `child-src` to `default-src`; 0.1 scored `object-src` at 0.15 and did not score `frame-src` at all, which had the weights pointing at the dead attack and away from the live one (Sections 4 and 6.7).

### Judgment calls you may want to argue with

1. **The scale runs upward now.** 0.2 is a 0 to 10 score where higher is better, and 0.1 was a 1 to 10 index where lower was better. Every number quoted from 0.1 in this document is on that old scale. The reasoning: the posture scores people actually meet in the wild run higher-is-better (OpenSSF Scorecard's 0 to 10, Mozilla Observatory, Lighthouse, and the letter grades from SSL Labs and securityheaders.com), while CVSS runs the other way because it measures the severity of one vulnerability and its readers know that convention going in. This number describes the posture of a control, and it will be read by developers and managers who will never open this document. The tell was that an earlier draft of 0.2 needed a warning label in Section 8 explaining that lower was better; a scale that has to be captioned is pointing the wrong way. Better to do it now, before anyone implements against a score or depends on one.
2. **The script cap.** `csp_score = 10 * min(weighted, p_script)` is the largest structural change in this version and the one most likely to be wrong in some edge case I have not thought of. It exists because 0.1 put a policy with no `script-src` and everything else perfect in the comfortable middle of its range with a reassuring label (Section 8).
3. **Script weight 0.40, object weight 0.05.** Moving script up from 0.35 and object down from 0.15 is a claim about how much plugin content still matters in 2026. I think it is obviously right; I also thought 0.15 was fine six months ago (Section 4).
4. **X-Frame-Options credited at 0.80 and 0.60**, where 0.1 allowed only 40% and 25% of the missing directive's value back. This follows from treating what is held back as deployment fragility, and reasonable people will land on different values (Section 7).
5. **The allowlist rows**, specifically 0.50 for 1-2 origins, 0.40 for 3+, and the flat 0.10 credit for adding a nonce without `'strict-dynamic'`. The count thresholds are round numbers, not measurements (Section 6.1).
6. **The 16-byte nonce cutoff.** CSP3 says SHOULD, not MUST, and treating a 12-byte nonce as no nonce at all is a sharp cliff for what is arguably still decent entropy (rule 8).
7. **Trusted Types closing 25% and 35% of the remaining gap.** The gap between the two tiers is small and I am not certain the `trusted-types` allowlist directive earns a separate tier at all (Section 6.1).
8. **Adding `frame-src` at 0.05 and paying for it out of the script weight.** Taking the 0.05 from script (0.45 down to 0.40) is defensible because the cap already governs any policy with a weak script directive, so the change is close to invisible where script is bad and small where script is good. The alternative was to shave the other five, which would have moved more numbers for less reason. Either way, every score computed under 0.1 or under an early draft of 0.2 is now a different number, which is the cost of a new category and the whole argument for `model_version` (Sections 4 and 8).

---

## 14. References

- [W3C Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [Mitigating XSS with a Strict Content Security Policy (Google)](https://csp.withgoogle.com/docs/strict-csp.html)
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- ["CSP Is Dead, Long Live CSP!" Weichselbaum, Spagnuolo, Lekies, Janc (CCS 2016)](https://dl.acm.org/doi/10.1145/2976749.2978363)
- [Bypassing CSP with Policy Injection (PortSwigger Research)](https://portswigger.net/research/bypassing-csp-with-policy-injection)
- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [csp-lab: experimenting with gathering CSP data / statistics](https://github.com/JGillam/csp-lab)

---

The practical point of all this is small and specific: when you hand someone a CSP finding, you should be able to say "this policy scores 2.1, here are the three directives that put it there, and here is what it looks like after you fix them," instead of "you have a CSP but it is not very good."

So please tear this apart. I want to know which rubric rows produce a number you disagree with, which of the judgment calls in Section 13 you think are wrong and why, and especially whether any real policy you score by hand comes out different from what this document says it should. Open an issue, and bring the header that broke it.
