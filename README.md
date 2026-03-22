# CSP Index

A risk-based index for evaluating the quality of Content Security Policy (CSP) headers.

Instead of treating CSP as a pass/fail checkbox, the CSP Index scores a policy on a **1–10 risk scale** based on how well it restricts each meaningful attack surface: script execution, object/plugin execution, frame embedding, form actions, base URI manipulation, and style injection. Categories are independently scored against a defined rubric and aggregated using a weighted formula.

## Read the Proposal

The full specification — including the scoring model, category weights, per-directive rubrics, modifier handling, and worked examples is in [`PROPOSAL.md`](./PROPOSAL.md).

## Status

This repository is in the proposal/RFC stage. The specification is open for community feedback before a reference implementation is built.

## Contributing

Issues and pull requests are welcome. If you have feedback on the scoring model, category weights, or rubric definitions, please use the discussions tab.

## License

TBD
