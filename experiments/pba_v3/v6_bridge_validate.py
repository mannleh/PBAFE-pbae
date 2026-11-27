"""Independent accounting validator for the bounded v6 bridge study.

CLI: python -m experiments.pba_v3.v6_bridge_validate --root RUN_DIRECTORY
Importing and validate_root are read-only and never run training. Only main emits
validation.json; failures are recorded and return a nonzero CLI exit code.
No runner, verifier, v5 scheduler, or v5 bootstrap is imported. This is accounting
validation, not an independent cryptographic verifier or prediction reproduction.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re

import numpy as np

SCENARIOS = ("mixed_recovery", "withholding_recovery")
METHODS = ("noaudit", "uniform", "adaptive", "neutral", "separated")
PASS, MISSING, FAIL = "PASS", "INCONCLUSIVE_EVIDENCE", "FAIL_POLICY"
TARGETS = frozenset((13, 15))
CORE_SOURCES = ("v6_bridge.py", "v5_response.py", "v5_common.py", "flcore.py",
                "verify.py", "codec.py", "repository.py", "run_c_consequence.py")
TIMINGS = frozenset(("audit_cpu_ms", "audit_wall_ms", "training_wall_ms", "evidence_build_wall_ms"))
MEAN_KEYS = {
    "bridge": ("applied_violating_rounds", "prevented_violating_rounds", "compliant_rounds_retained",
               "longest_retention_streak", "discarded_steps_fraction", "missing_finding_rounds",
               "mixed_fail_missing_rounds", "inconclusive_only_rounds", "discarded_compliant_steps"),
    "totals": ("audit_total_bytes", "discarded_training_steps", "rejected_rounds", "attack_rounds",
               "local_training_steps"),
    "final": ("f1", "balanced_accuracy", "precision", "recall"),
}
PAIRED_KEYS = ("applied_violating_rounds", "compliant_rounds_retained",
               "longest_retention_streak", "discarded_steps_fraction")
PRIMARY = {("neutral", "adaptive"): "compliant_rounds_retained",
           ("neutral", "uniform"): "applied_violating_rounds",
           ("separated", "neutral"): "longest_retention_streak"}


class ValidationError(ValueError):
    """Explicit validation failure, unaffected by python -O."""


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def compare(actual, expected, path="value"):
    """Strict structure/counters; tiny roundoff tolerance only for floats."""
    if isinstance(expected, dict):
        require(isinstance(actual, dict) and actual.keys() == expected.keys(), f"{path}: keys differ")
        for key in expected:
            compare(actual[key], expected[key], f"{path}.{key}")
    elif isinstance(expected, list):
        require(isinstance(actual, list) and len(actual) == len(expected), f"{path}: length differs")
        for i, (a, e) in enumerate(zip(actual, expected)):
            compare(a, e, f"{path}[{i}]")
    elif isinstance(expected, bool) or expected is None or isinstance(expected, str):
        require(type(actual) is type(expected) and actual == expected, f"{path}: {actual!r} != {expected!r}")
    elif isinstance(expected, int):
        require(type(actual) is int and actual == expected, f"{path}: {actual!r} != {expected!r}")
    else:
        require(isinstance(actual, (int, float)) and not isinstance(actual, bool)
                and math.isfinite(actual) and math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12),
                f"{path}: {actual!r} != {expected!r}")


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def bootstrap(values, confidence=.95):
    """Independent percentile mean bootstrap; 20,000 resamples/RNG 776655."""
    sample = np.asarray(values, dtype=np.float64)
    require(sample.ndim == 1 and np.isfinite(sample).all(), "bootstrap: invalid sample")
    size = len(sample)
    result = {"n": size, "mean": float(np.mean(sample)) if size else None, "ci": None}
    if size >= 2:
        indices = np.random.default_rng(776655).integers(0, size, size=(20000, size))
        replicates = np.sum(sample[indices], axis=1) / size
        tail = (1 - confidence) / 2
        result.update(ci=np.quantile(replicates, [tail, 1 - tail]).tolist(),
                      confidence=confidence, resamples=20000, unit="matched seed")
    return result


def withholding_ids(seed, clients):
    pool = [c for c in range(clients) if c not in TARGETS]
    draw = np.random.default_rng(np.random.SeedSequence([seed, 96103])).choice(pool, 2, replace=False)
    return sorted(int(c) for c in draw)


class ObservedSchedule:
    """Independent replay accepting only prior local outcomes, never labels."""
    def __init__(self, method, clients):
        self.method, self.clients = method, clients
        self.risk = np.zeros(clients)
        self.due = {}

    def choose(self, seed, round_id, budget):
        u = np.random.default_rng(np.random.SeedSequence([seed, round_id, 91001])).uniform(
            np.finfo(float).tiny, 1, self.clients)
        weights = np.ones(self.clients) if self.method == "uniform" else self.risk + max(.05, 1 / self.clients)
        priority = -np.log(u) / weights
        ordered = sorted(range(self.clients), key=lambda c: (priority[c], c))
        if self.method != "separated":
            return sorted(ordered[:budget])
        due = [c for c, when in self.due.items() if when <= round_id]
        retry = sorted(due, key=lambda c: (self.due[c], -np.log(u[c]), c))[:1]
        chosen = retry + [c for c in ordered if c not in self.due][:budget - len(retry)]
        chosen += [c for c in ordered if c not in chosen][:budget - len(chosen)]
        return sorted(chosen)

    def observe(self, outcomes, round_id):
        for c, outcome in outcomes.items():
            if outcome.startswith("FAIL_"):
                self.risk[c] += 1
                self.due.pop(c, None)
            elif outcome == MISSING:
                if self.method == "adaptive":
                    self.risk[c] += .5
                if self.method == "separated":
                    self.due[c] = round_id + 3
            elif outcome == PASS:
                self.due.pop(c, None)


def request_plan(chosen, slots, targets, withheld):
    """Expected Reader call order, including early exit at local faults."""
    requests = ["bulletin", "snapshot", "policy"] if slots else []
    for c in slots:
        prefix = f"record/{c}/"
        requests.extend(prefix + suffix for suffix in ("roster", "roster_proof", "state", "state_proof"))
        if c not in chosen:
            requests.append(prefix + "disposition")
        else:
            requests.append(prefix + "receipt")
            if c not in targets:
                requests.append(prefix + "opening")
                if c not in withheld:
                    requests.append(prefix + "update")
    return requests


def payload_sizes(round_id, chosen, targets, counts, dimension):
    """Exact canonical lengths; all digests/signatures have fixed-width encodings.

    No keys, updates, source objects, model, or training are regenerated.
    """
    h = "0" * 64
    envelope = lambda body: {"body": body, "sig": "0" * 128}
    clients = len(counts)
    policy = {"version": "declared-fedavg-v2", "max_count": 10**6,
              "status_rule": "valid-submissions-accepted;independent-close-for-absence"}
    public = {
        "bulletin": envelope({"version": "PBA/2", "round": round_id, "model_hash": h,
            "roster_root": h, "policy_hash": h, "deadline": round_id * 1000 + 900,
            "K": clients, "dimension": dimension}),
        "snapshot": envelope({"version": "PBA/2", "round": round_id, "bulletin_hash": h,
            "K": clients, "state_root": h, "denominator": sum(counts[c] for c in chosen if c not in targets),
            "result_digest": h}),
        "policy": policy,
    }
    sizes = {key: len(canonical(value)) for key, value in public.items()}
    proof_size = len(canonical([h] * (clients - 1).bit_length()))
    for c in range(clients):
        present, attacked = c in chosen, c in targets
        status = "REJECTED" if attacked else "ACCEPTED" if present else "ABSENT"
        state = {"slot": c, "client_id": c, "status": status,
                 "numerator": counts[c] if present and not attacked else 0,
                 "policy_count": counts[c] if present and not attacked else 0,
                 "policy_version": policy["version"], "receipt_digest": h if present else None}
        receipt = envelope({"version": "PBA/2", "round": round_id, "model_hash": h,
            "bulletin_hash": h, "client_id": c, "update_digest": h,
            "declared_count": counts[c], "status": "SUBMITTED"})
        disposition = envelope({"bulletin_hash": h, "client_id": c, "slot": c, "status": "ABSENT"})
        for name, length in {
            "roster": len(canonical({"slot": c, "client_id": c, "eligibility": "ENROLLED"})),
            "roster_proof": proof_size, "state": len(canonical(state)), "state_proof": proof_size,
            "receipt": len(canonical(receipt)), "disposition": len(canonical(disposition)),
            "opening": 32, "update": 8 * dimension,
        }.items():
            sizes[f"record/{c}/{name}"] = length
    return sizes


def bridge_from_trace(trace, restore_round=41):
    """Recompute bridge outcomes from decisions, preserving right censoring."""
    streak = longest = 0
    for row in trace:
        streak = streak + 1 if row["rejected"] else 0
        longest = max(streak, longest)
    bad = [r for r in trace if r["attack_targets"]]
    compliant = [r for r in trace if not r["attack_targets"]]
    applies = [r["round"] - restore_round for r in trace
               if r["round"] >= restore_round and not r["rejected"]]
    steps = sum(r["local_steps"] for r in trace)
    require(steps > 0, "trace has no training steps")
    return {
        "applied_violating_rounds": sum(not r["rejected"] for r in bad),
        "prevented_violating_rounds": sum(r["rejected"] for r in bad),
        "compliant_rounds_retained": sum(r["rejected"] for r in compliant),
        "compliant_missing_retained": sum(r["rejected"] and r["outcome"] == MISSING for r in compliant),
        "compliant_rounds": len(compliant),
        "missing_finding_rounds": sum(r["missing_requests"] > 0 for r in trace),
        "mixed_fail_missing_rounds": sum(bool(r["outcome"] and r["outcome"].startswith("FAIL_"))
                                         and r["missing_requests"] > 0 for r in trace),
        "inconclusive_only_rounds": sum(r["outcome"] == MISSING for r in trace),
        "longest_retention_streak": longest,
        "post_restore_first_apply_delay": min(applies) if applies else None,
        "post_restore_apply_censored": not bool(applies),
        "discarded_steps_fraction": sum(r["local_steps"] for r in trace if r["rejected"]) / steps,
        "discarded_compliant_steps": sum(r["local_steps"] for r in compliant if r["rejected"]),
    }


def validate_cell(cell, counts, *, features=193, hidden=32, selected=10, rounds=60,
                  attack_start=21, attack_end=60, missing_start=21, missing_end=40, restore_round=41):
    """Validate a trace; optional design parameters are for synthetic tests only."""
    scenario, method, seed = cell["scenario"], cell["method"], cell["seed"]
    require(scenario in SCENARIOS and method in METHODS, "unknown scenario/method")
    require(type(seed) is int and type(rounds) is int, "seed/rounds must be integers")
    require(len(counts) > max(TARGETS) and all(type(n) is int and n > 0 for n in counts), "invalid counts")
    clients, dimension = len(counts), features * hidden + 2 * hidden + 1
    compare(cell["rounds"], rounds, "rounds")
    compare(cell["clients"], clients, "clients")
    compare(cell["dimension"], dimension, "dimension")
    compare(cell["train_rows"], sum(counts), "train_rows")
    audited = method != "noaudit"
    compare(cell["audit_budget"], 3 if audited else 0, "audit_budget")
    compare(cell["response_policy"], "reject FAIL/INCONCLUSIVE; retain previous model; no replacement", "response_policy")
    withheld_ids = withholding_ids(seed, clients)
    compare(cell["withholding_ids"], withheld_ids, "withholding_ids")
    scheduler = ObservedSchedule(method, clients)
    training_rng = np.random.default_rng(seed)
    initial = np.concatenate((training_rng.normal(0, .05, features * hidden), np.zeros(hidden),
                              training_rng.normal(0, .05, hidden), np.zeros(1)))
    initial_hash = hashlib.sha256(initial.tobytes()).hexdigest()
    compare(cell["initial_model_sha256"], initial_hash, "initial_model_sha256")
    trace = cell["round_rows"]
    require(isinstance(trace, list) and len(trace) == rounds, "round_rows: incomplete trace")
    totals = Counter({key: 0 for key in (
        "attack_rounds", "attacked_updates_applied", "attacked_records_applied", "prevented_bad_rounds",
        "rejected_rounds", "honest_rounds_rejected", "audit_calls", "full_audit_calls", "actual_replays",
        "aggregate_verified", "inconclusive_calls", "audit_requests", "audit_missing_requests",
        "audit_request_bytes", "audit_response_payload_bytes", "audit_response_framing_bytes", "audit_total_bytes",
        "local_training_steps", "local_rows_processed", "discarded_training_steps", "discarded_rows_processed",
        "application_upload_payload_bytes", "application_download_payload_bytes", "candidate_download_payload_bytes",
        "response_extra_payload_bytes", "records_processed", "updates_processed")})
    previous_hash, schedule = initial_hash, []
    for rid, row in enumerate(trace, 1):
        label = f"round[{rid}]"
        compare(row["round"], rid, label)
        chosen = sorted(int(c) for c in training_rng.choice(clients, selected, replace=False))
        compare(row["chosen"], chosen, label + ".chosen (independent training RNG)")
        schedule.append(chosen)
        targets = sorted(TARGETS.intersection(chosen)) if scenario == "mixed_recovery" and attack_start <= rid <= attack_end else []
        withheld = withheld_ids if missing_start <= rid <= missing_end else []
        compare(row["attack_targets"], targets, label + ".attack_targets")
        compare(row["withholding_slots"], withheld, label + ".withholding_slots")
        objects = [f"record/{c}/" + ("opening" if c in chosen else "disposition") for c in withheld] if audited else []
        compare(row["withheld_objects"], objects, label + ".withheld_objects")
        slots = scheduler.choose(seed, rid, 3) if audited else []
        compare(row["audit_slots"], slots, label + ".audit_slots (observations only, exact b=3)")
        local = {c: FAIL if c in targets else MISSING if c in withheld else PASS for c in slots}
        compare(row["record_outcomes"], {str(c): v for c, v in local.items()}, label + ".record_outcomes")
        outcome = FAIL if FAIL in local.values() else MISSING if MISSING in local.values() else PASS if audited else None
        compare(row["outcome"], outcome, label + ".outcome (failure precedence)")
        scheduler.observe(local, rid)
        rejected = outcome in (FAIL, MISSING)
        compare(row["rejected"], rejected, label + ".rejected (outcome-only controller)")
        compare(row["previous_model_sha256"], previous_hash, label + ".previous_model_sha256")
        applied_hash = row["applied_model_sha256"]
        require(isinstance(applied_hash, str) and re.fullmatch("[0-9a-f]{64}", applied_hash), label + ": malformed model hash")
        if rejected:
            compare(applied_hash, previous_hash, label + ".reject must retain hash")
        previous_hash = applied_hash
        requests = request_plan(chosen, slots, targets, withheld)
        compare(row["requests"], requests, label + ".requests")
        missing = len(set(requests).intersection(objects))
        request_bytes = sum(4 + len(canonical({"get": name})) for name in requests)
        sizes = payload_sizes(rid, chosen, targets, counts, dimension) if audited else {}
        payload = sum(sizes[name] for name in requests if name not in objects)
        framing = 5 * len(requests)
        trained = sum(min(128, counts[c]) for c in chosen)
        for field, expected in dict(audit_requests=len(requests), missing_requests=missing,
                request_bytes=request_bytes, payload_bytes=payload, framing_bytes=framing,
                audit_bytes=request_bytes + payload + framing, trained_rows=trained, local_steps=selected).items():
            compare(row[field], expected, label + "." + field)
        bad = bool(targets)
        totals.update(dict(attack_rounds=int(bad), attacked_updates_applied=int(bad and not rejected),
            attacked_records_applied=len(targets) if not rejected else 0, prevented_bad_rounds=int(bad and rejected),
            rejected_rounds=int(rejected), honest_rounds_rejected=int(not bad and rejected),
            audit_calls=int(audited), inconclusive_calls=int(outcome == MISSING), audit_requests=len(requests),
            audit_missing_requests=missing, audit_request_bytes=request_bytes, audit_response_payload_bytes=payload,
            audit_response_framing_bytes=framing, audit_total_bytes=request_bytes + payload + framing,
            local_training_steps=selected, local_rows_processed=trained,
            discarded_training_steps=selected if rejected else 0, discarded_rows_processed=trained if rejected else 0,
            application_upload_payload_bytes=selected * dimension * 8,
            application_download_payload_bytes=selected * dimension * 8, candidate_download_payload_bytes=dimension * 8,
            records_processed=len(slots), updates_processed=sum(c in chosen and v == PASS for c, v in local.items())))
    compare(cell["final_model_sha256"], previous_hash, "final_model_sha256")
    compare(cell["selection_schedule_sha256"], hashlib.sha256(json.dumps(schedule).encode()).hexdigest(),
            "selection_schedule_sha256")
    compare({k: v for k, v in cell["totals"].items() if k not in TIMINGS}, dict(totals), "totals")
    for key in TIMINGS:
        value = cell["totals"][key]
        require(type(value) in (int, float) and math.isfinite(value) and value >= 0, f"timing: invalid {key}")
    bridge = bridge_from_trace(trace, restore_round)
    compare(cell["bridge"], bridge, "bridge")
    checkpoints = [r for r in range(1, rounds + 1) if r % 10 == 0 or r == rounds]
    compare([r["round"] for r in cell["trajectory"]], checkpoints, "trajectory rounds")
    compare(cell["final"], {k: v for k, v in cell["trajectory"][-1].items() if k != "round"}, "final/trajectory")
    for point in cell["trajectory"]:
        for key in MEAN_KEYS["final"]:
            require(type(point[key]) in (float, int) and math.isfinite(point[key]) and 0 <= point[key] <= 1,
                    f"trajectory: invalid {key}")
    return {"totals": dict(totals), "bridge": bridge}


def recompute_summary(cells):
    """Rebuild all summaries, including the three prespecified primary contrasts."""
    seeds = sorted({r["seed"] for r in cells})
    means, groups, paired = {}, {}, {}
    for scenario in SCENARIOS:
        for method in METHODS:
            group = sorted((r for r in cells if (r["scenario"], r["method"]) == (scenario, method)),
                           key=lambda r: r["seed"])
            compare([r["seed"] for r in group], seeds, f"summary seed pairing {scenario}/{method}")
            groups[scenario, method] = group
            metrics = {key: bootstrap([r[section][key] for r in group])
                       for section, keys in MEAN_KEYS.items() for key in keys}
            delays = [r["bridge"]["post_restore_first_apply_delay"] for r in group
                      if not r["bridge"]["post_restore_apply_censored"]]
            metrics["post_restore_first_apply_delay"] = {
                "conditional_mean": float(np.mean(delays)) if delays else None,
                "observed": len(delays), "censored": len(group) - len(delays), "window_rounds": 20}
            means[scenario + "/" + method] = metrics
        for left, right in PRIMARY:
            a, b = groups[scenario, left], groups[scenario, right]
            differences = lambda section, key: [x[section][key] - y[section][key] for x, y in zip(a, b)]
            metrics = {key: bootstrap(differences("bridge", key)) for key in PAIRED_KEYS}
            metrics["f1"] = bootstrap(differences("final", "f1"))
            if scenario == "mixed_recovery":
                key = PRIMARY[left, right]
                metrics["primary"] = {"metric": key, **bootstrap(differences("bridge", key), 1 - .05 / 3)}
            paired[scenario + "/" + left + "-" + right] = metrics
    return dict(n_runs=len(cells), n_seeds=len(seeds), means=means, paired=paired,
        inference_scope="training/scheduling seed variation; one fixed data partition; no population generalization",
        primary_family_size=3, primary_confidence=1 - .05 / 3,
        ci_method="20000 paired seed percentile bootstrap resamples", source="all completed rows; no exclusions")


def check_control_sources(runner_source, response_source):
    """Parse source as data. Bounded guards, not a proof against arbitrary Python."""
    runner, response = ast.parse(runner_source), ast.parse(response_source)
    functions = {n.name: n for n in response.body if isinstance(n, ast.FunctionDef)}
    expected = ast.parse('''
def reject_round(outcome):
    return outcome is not None and (outcome.startswith("FAIL_") or outcome == INCONCLUSIVE)
def next_model(previous, published, outcome):
    return previous.copy() if reject_round(outcome) else previous + published / SCALE
''')
    for template in expected.body:
        actual = functions[template.name]
        body = [n for n in actual.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
                                               and isinstance(n.value.value, str))]
        compare(ast.dump(actual.args), ast.dump(template.args), template.name + " signature")
        compare([ast.dump(n) for n in body], [ast.dump(n) for n in template.body], template.name + " outcome-only body")
    cell = next(n for n in runner.body if isinstance(n, ast.FunctionDef) and n.name == "run_cell")
    def calls(name):
        return [n for n in ast.walk(cell) if isinstance(n, ast.Call) and ast.unparse(n.func) == name]
    allowed = {"Scheduler": "Scheduler(method, clients=client_count)",
               "scheduler.choose": "scheduler.choose(seed, r + 1, budget)",
               "scheduler.observe": "scheduler.observe(record_outcomes)",
               "reject_round": "reject_round(outcome)", "next_model": "next_model(w, aggregate, outcome)"}
    locations = {}
    for name, text in allowed.items():
        found = calls(name)
        require(len(found) == 1, f"control boundary: expected one {name} call")
        compare(ast.dump(found[0]), ast.dump(ast.parse(text, mode="eval").body), "control boundary " + name)
        locations[name] = found[0].lineno
    attributes = [n.attr for n in ast.walk(cell) if isinstance(n, ast.Attribute)
                  and isinstance(n.value, ast.Name) and n.value.id == "scheduler"]
    compare(sorted(attributes), ["choose", "observe"], "scheduler interface")
    removal, verifier = calls("withhold"), calls("audit")
    require(len(removal) == len(verifier) == 1 and removal[0].lineno < locations["scheduler.choose"]
            < verifier[0].lineno < locations["scheduler.observe"] < locations["reject_round"]
            < locations["next_model"], "pre-challenge withholding/observation/controller ordering")
    targets = [n for n in ast.walk(cell) if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "targets" for t in n.targets)]
    require(len(targets) == 1 and targets[0].lineno > locations["next_model"],
            "hidden labels must enter accounting after the action")
    return {"observation_only_schedule_replayed": True, "outcome_only_controller_ast": True,
            "pre_challenge_withholding_ast": True}


def strict_json(text, label):
    def invalid_constant(value):
        raise ValidationError(f"{label}: non-finite JSON constant {value}")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"{label}: duplicate JSON key {key}")
            result[key] = value
        return result
    return json.loads(text, parse_constant=invalid_constant, object_pairs_hook=unique)


def read_json(path):
    return strict_json(Path(path).read_text(encoding="utf-8-sig"), str(path))


def check_design(cfg, *, evaluation=False, expected_cells=None):
    """Development count is configurable; evaluation cannot relax frozen design."""
    compare({k: cfg[k] for k in ("rounds", "scenarios", "methods", "budget", "attack_rounds",
                                "missing_rounds", "restoration_round")},
            dict(rounds=60, scenarios=list(SCENARIOS), methods=list(METHODS), budget=3,
                 attack_rounds=[21, 60], missing_rounds=[21, 40], restoration_round=41), "frozen config")
    require(type(cfg["seeds"]) is int and cfg["seeds"] >= 1 and type(cfg["seed_start"]) is int,
            "seed config must contain positive integer seed count and integer start")
    seeds = list(range(cfg["seed_start"], cfg["seed_start"] + cfg["seeds"]))
    if evaluation:
        compare(seeds, list(range(310001, 310021)), "frozen evaluation seeds")
    else:
        require(all(309991 <= s <= 309999 for s in seeds), "development seeds must be 309991..309999")
    cells = len(seeds) * len(SCENARIOS) * len(METHODS)
    if expected_cells is not None:
        compare(cells, expected_cells, "explicit expected cell count")
    for key, value in dict(selected=10, hidden=32, lr=.03).items():
        if key in cfg:
            compare(cfg[key], value, "frozen config." + key)
    return seeds, cells


def validate_root(root, *, expected_cells=None):
    """Read-only validation; automatically enforce frozen design for evaluation/."""
    root = Path(root).resolve()
    report = {"status": "FAIL", "root": str(root), "errors": [], "checks": {},
              "stage": "evaluation" if root.name.lower() == "evaluation" else "development",
              "limitations": ["Not an independent cryptographic verification.",
                  "Accepted updates and classifier predictions are not independently rerun.",
                  "Timings are finite/nonnegative checked only; no per-round timings exist.",
                  "Protocol hash is recorded now, not independently anchored at freeze."]}
    errors = report["errors"]
    try:
        require(not (root / "FAILED.json").exists(), "FAILED.json exists; no failed run may be ignored")
        cfg, done = read_json(root / "config.json"), read_json(root / "COMPLETE.json")
        seeds, count = check_design(cfg, evaluation=report["stage"] == "evaluation", expected_cells=expected_cells)
        report.update(expected_cells=count, expected_rounds=count * 60)
        compare(done["status"], "COMPLETED", "completion status")
        compare(done["expected"], count, "completion expected")
        compare(done["completed"], count, "completion count")
        source_dir = Path(__file__).resolve().parent
        sources = cfg["source_sha256"]
        require(isinstance(sources, dict), "source hash manifest must be a mapping")
        source_paths = {Path(p).resolve(): h for p, h in sources.items()}
        require(len(source_paths) == len(sources), "aliased source paths")
        for name in CORE_SOURCES:
            require((source_dir / name).resolve() in source_paths, f"missing source hash: {name}")
        for path, expected_hash in source_paths.items():
            compare(sha256(path), expected_hash, "source hash " + str(path))
        report["checks"]["source_sha256"] = sources
        protocol = source_dir / "results" / "bridge_v6_20261023" / "PROTOCOL.md"
        report["checks"]["protocol_sha256"] = sha256(protocol)
        report["checks"]["validator_sha256"] = sha256(Path(__file__))
        report["checks"]["control_boundaries"] = check_control_sources(
            (source_dir / "v6_bridge.py").read_text(encoding="utf-8-sig"),
            (source_dir / "v5_response.py").read_text(encoding="utf-8-sig"))
        data_dir = Path(cfg["data_dir"])
        compare(sorted(cfg["data_sha256"]), ["client_indices.json", "unsw_subset.npz"], "data hash manifest")
        for name, expected_hash in cfg["data_sha256"].items():
            compare(sha256(data_dir / name), expected_hash, "data hash " + name)
        report["checks"]["data_sha256"] = cfg["data_sha256"]
        compare(cfg["numpy_version"], np.__version__, "NumPy version for exact seeded replay")
        partition = read_json(data_dir / "client_indices.json")
        require(isinstance(partition, list) and len(partition) == 30 and all(partition), "partition: 30 nonempty clients required")
        counts = [len(block) for block in partition]
        with np.load(data_dir / "unsw_subset.npz", allow_pickle=False) as data:
            train_shape, test_shape = data["X_train"].shape, data["X_test"].shape
            require(len(train_shape) == len(test_shape) == 2 and train_shape[1] == test_shape[1] == 193,
                    "data: expected 193 training/test features")
            require(data["y_train"].shape == (train_shape[0],) and data["y_test"].shape == (test_shape[0],), "data: label shape")
        ids = [i for block in partition for i in block]
        require(all(type(i) is int and 0 <= i < train_shape[0] for i in ids)
                and len(set(ids)) == len(ids) == train_shape[0], "partition: must cover training rows without overlap")
        rows = []
        with (root / "rows.jsonl").open(encoding="utf-8-sig") as stream:
            for line_no, line in enumerate(stream, 1):
                require(bool(line.strip()), f"rows.jsonl:{line_no}: empty checkpoint row")
                rows.append(strict_json(line, f"rows.jsonl:{line_no}"))
        expected = {(s, m, seed) for s in SCENARIOS for m in METHODS for seed in seeds}
        keys = [(r["scenario"], r["method"], r["seed"]) for r in rows]
        require(len(rows) == count and len(set(keys)) == count and set(keys) == expected,
                f"cell coverage: require all {count} unique cells, no omissions/duplicates/extras")
        report["checks"]["cell_coverage"] = {"cells": len(rows), "unique_cells": len(set(keys))}
        valid = 0
        for row in rows:
            label = f"{row['scenario']}/{row['method']}/{row['seed']}"
            try:
                validate_cell(row, counts)
                compare(row["test_rows"], test_shape[0], label + ".test_rows")
                valid += 1
            except (ValidationError, KeyError, TypeError, ValueError, IndexError, OverflowError) as exc:
                errors.append(f"{label}: {type(exc).__name__}: {exc}")
        report["checks"]["trace_accounting"] = {"validated_cells": valid, "total_cells": len(rows),
                                                 "rounds_seen": sum(len(r["round_rows"]) for r in rows)}
        for seed in seeds:
            matched = [r for r in rows if r["seed"] == seed]
            for key in ("initial_model_sha256", "selection_schedule_sha256"):
                require(len({r[key] for r in matched}) == 1, f"seed {seed}: mismatched {key} across scenarios/methods")
            require(len({tuple(r["withholding_ids"]) for r in matched}) == 1, f"seed {seed}: mismatched withholding IDs")
        report["checks"]["paired_seeds"] = len(seeds)
        if not errors:
            compare(read_json(root / "summary.json"), recompute_summary(rows), "summary")
            report["checks"]["summary"] = {"all_means_and_paired_checked": True, "primary_contrasts": 3,
                "resamples": 20000, "resampling_seed": 776655, "primary_confidence": 1 - .05 / 3,
                "intervals_estimable": len(seeds) >= 2}
    except (OSError, ValidationError, KeyError, TypeError, ValueError, IndexError, StopIteration, OverflowError) as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    report["status"] = "PASS" if not errors else "FAIL"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="completed development or evaluation folder")
    parser.add_argument("--expected-cells", type=int, help="optional expected count; cannot relax evaluation design")
    args = parser.parse_args(argv)
    report = validate_root(args.root, expected_cells=args.expected_cells)
    destination = args.root / "validation.json"
    # No directory creation and no implicit/import-time artifacts.
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf8")
    print(json.dumps({"status": report["status"], "errors": report["errors"], "path": str(destination.resolve())}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
