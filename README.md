# CSP Index

I got tired of reading scanner output that grades a Content-Security-Policy header as present or absent and calls it done. A policy of `script-src *` and a policy built on `'strict-dynamic'` with a per-request nonce are both "present," and they are not in the same universe.

The CSP Index scores the header string from **0 to 10, where higher is better**. It resolves the policy the way a browser actually would (fallback chains, duplicate directives, `'strict-dynamic'`, `sandbox`, nonce validity), scores seven attack-surface categories against published rubrics, and combines them into a weighted number. The one rule worth knowing before you read anything else: your score can never be higher than your `script-src`, because with script execution open every other directive is academic.

## The proposal

Everything (the categories and weights, the resolution rules, the per-category rubrics, the modifier headers, the formula, and four worked examples with the arithmetic shown) is in [`PROPOSAL.md`](./PROPOSAL.md). It is written to be implementable, so if something in it is ambiguous, that is a bug.

## Status

RFC, version 0.2.0. There is no reference implementation yet, deliberately: I want to argue about the model in public before anyone codes against it. Version 0.2 is a substantial correction of 0.1, mostly in places where 0.1 contradicted the CSP Level 3 spec, and there is a section at the end of the proposal listing exactly what changed and which changes are judgment calls.

## Feedback

This is the part I actually want. Open an issue if you find a rubric row that produces a number you disagree with, a policy the rules resolve incorrectly, or an arithmetic error in the worked examples. Use the discussions tab for the broader "your weights are wrong and here is why" conversation, which I am expecting and want to have now, before people start depending on the scores.

## Companion project

[csp-lab](https://github.com/JGillam/csp-lab) is where the data collection lives. Its `docs/csp-component-classifications.md` is the six-component classification framework, applied across a dataset of 750,000+ sites, that the first six of the seven categories here grew out of.

## License

TBD.
