# Frozen bounded bridge experiment, 2026-10-23

## Material Passport
- Stage: author-authorized bounded extension, local UNSW-NB15 application experiment.
- Status at freeze: design fixed before development or evaluation outcomes.
- Contribution: connect evidence availability, observed audit scheduling, and reject-and-retain costs. No new scheduler, privacy mechanism, replacement aggregate, or classifier superiority claim.

## Fixed design
- Reuse v5 data/partition, 193 features, 30 clients, 10 selected per round, 32-unit MLP, 6241 parameters, 60 rounds, one local minibatch step, lr .03.
- Evaluation seeds 310001--310020 (20 paired seeds), separate development seeds 309991--309999. Existing v5 seeds not pooled.
- Scenarios: mixed_recovery = illegal exclusion of clients 15/13 when selected, rounds 21--60, plus temporary evidence withholding in rounds 21--40; withholding_recovery = withholding only, no illegal exclusion.
- Two fixed withholding slots per seed from a deterministic permutation/choice independent of training and audit randomness, excluding clients 15/13. Same slots across methods/scenarios.
- Before audit selection, remove the accepted record opening, or absent record's signed close disposition. This makes each target locally inconclusive whether or not it trained. Restore all evidence from round 41. The server candidate and commitments are not altered by withholding; ephemeral audit evidence can be fetched again in later rounds, not historical replay.
- Methods: noaudit, uniform, adaptive, neutral, separated. All audited methods check exactly b=3 distinct slots each round, including healthy rounds. No free recovery probes; same shared random-priority mechanism as v5.
- Controller unchanged: apply on PASS, retain previous model on FAIL or INCONCLUSIVE. No hidden labels or honest replacement in control path.

## Outcomes and analysis fixed before runs
- All cells and all completed seeds reported; no result-driven seed/target/hyperparameter selection.
- Primary family of three paired contrasts in mixed_recovery: (1) neutral minus adaptive compliant rounds retained; (2) neutral minus uniform applied violating rounds; (3) separated minus neutral longest consecutive retention streak. Two-sided 98.333333% percentile-bootstrap intervals (Bonferroni familywise alpha .05), 20000 resamples, fixed resampling RNG 776655.
- Other mean and paired 95% CIs descriptive. Analysis unit is training/scheduling seed, conditional on one fixed data split and client partition.
- Report both scenarios separately: applied violating rounds, compliant retained rounds, wasted local steps, maximum retention streak, additional audit bytes, final F1, and post-restoration first-application delay (censor runs with none by round 60).
- Compliant retention caused by missing evidence is a conservative control cost, not an integrity false positive.
- No universal scheduler ordering or F1 recovery is an expected/success condition. Fixed targets and missing-object mechanism limit generality.

## Verification and stopping
- Unit tests: outcome-only controller, selected/absent withholding, failure precedence, fixed disjoint targets, pure-withholding uniform-neutral equality, counters/censoring, matching schedules, no-missing equivalence with old runner.
- Smoke development on a separate seed, then freeze final source hashes and run 200 evaluation cells (12000 rounds). Per-cell durable checkpoint, explicit COMPLETE only after all jobs; no treating partial outputs as complete.
- Recompute counters and paired intervals from round traces with a separate validator; bounded deterministic rerun checks excluding timings. No full verifier independence claim.
- After this one extension, update current manuscript's experiment/methods/abstract/conclusion only where supported; build and inspect resulting PDF. Do not expand to new datasets/algorithms or change archived manuscripts.
