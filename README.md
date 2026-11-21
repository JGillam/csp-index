# CSP Index

I got tired of reading scanner output that grades a Content-Security-Policy header as present or absent and calls it done. A policy of `script-src *` and a policy built on `'strict-dynamic'` with a per-request nonce are both "present," and they are not in the same universe.

The CSP Index scores the header string from **0 to 10, where higher is better**. It resolves the policy the way a browser actually would (fallback chains, duplicate directives, `'strict-dynamic'`, `sandbox`, nonce validity), scores eight categories against published rubrics, and combines them into a weighted number. Two rules worth knowing before you read anything else. Four fifths of your score can never be higher than your `script-src`, because with script execution open nearly every other directive is academic. The last fifth is for the two directives that are not (i.e. `connect-src` and `img-src`, which limit where code already running in your page can send data).

## The proposal

Everything (the categories and weights, the resolution rules, the per-category rubrics, the modifier headers, the formula, and six worked examples with the arithmetic shown) is in [`PROPOSAL.md`](./PROPOSAL.md). It is written to be implementable, so if something in it is ambiguous, that is a bug.

## Status

RFC, version 0.3.0. There is now a reference implementation: the calculator at [mechanicaldrake.com/lab/csp-index](https://mechanicaldrake.com/lab/csp-index) scores a policy using the rules in `PROPOSAL.md`, and it runs entirely in your browser, so the policy you paste never leaves your machine. The model is still open for argument, which is why it lives here as an RFC. Version 0.2 was a substantial correction of 0.1, mostly in places where 0.1 contradicted the CSP Level 3 spec. Version 0.3 is smaller: it adds a Data Egress category, after an incident showed me what 0.2 could not see, and it turns one rule the right way round. Every 0.2 score is a different number under 0.3. There are two sections at the end of the proposal listing exactly what changed in each version, what I tested and threw away, and which changes are judgment calls.

## Feedback

This is the part I actually want. Open an issue if you find a rubric row that produces a number you disagree with, a policy the rules resolve incorrectly, or an arithmetic error in the worked examples. Use the discussions tab for the broader "your weights are wrong and here is why" conversation, which I am expecting and want to have now, before people start depending on the scores.

## Companion project

[csp-lab](https://github.com/JGillam/csp-lab) is where the data collection lives. Its `docs/csp-component-classifications.md` is the six-component classification framework, applied across a dataset of 750,000+ sites, that the first six of the eight categories here grew out of.

## License

TBD.
