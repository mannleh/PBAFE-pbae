"""Independent output audit of the v5 decision experiment.

Recomputes trace denominators, counters and paired means, not a full experiment
rerun. Independently reconstructs primary bootstrap draws with NumPy, without
calling the study's analysis functions. Does not infer scientific generality.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import sys


METHODS = ('uniform', 'adaptive', 'neutral', 'separated')
SCENARIOS = ('honest', 'integrity_only', 'mixed', 'recovery',
             'moving_integrity', 'moving_mixed', 'withholding_only')
ARMS = ('clean_noaudit', 'drop_noaudit', 'drop_uniform_b3', 'drop_neutral_b3',
        'drop_separated_b3', 'drop_full_b30')
MISSING = 'INCONCLUSIVE_EVIDENCE'
FAIL = 'FAIL_POLICY'
PASS = 'PASS'


def read(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Audit:
    def __init__(self):
        self.checks = 0
        self.errors = []
        self.sections = {}

    def check(self, condition, description):
        self.checks += 1
        if not condition:
            self.errors.append(description)

    def same(self, actual, expected, description):
        if actual is None or expected is None:
            equal = actual is expected
        elif isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
            equal = math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-10)
        else:
            equal = actual == expected
        self.check(equal, f'{description}: actual={actual!r}, expected={expected!r}')


def primary_bootstrap(a, differences, reported, label):
    """Reconstruct the documented resampling procedure, not its helper call."""
    import numpy as np
    observations = np.asarray(differences, dtype=float)
    indices = np.random.default_rng(776655).integers(
        0, observations.size, size=(20000, observations.size))
    replicate_means = np.sum(observations[indices], axis=1) / observations.size
    intervals = np.quantile(replicate_means, [.0125, .9875])
    a.same(reported['n'], len(differences), label+' bootstrap sampling unit')
    a.same(reported['resamples'], 20000, label+' bootstrap resamples')
    a.same(reported['confidence'], .975, label+' bootstrap confidence')
    for index, value in enumerate(intervals):
        a.same(reported['ci'][index], float(value), label+' independently regenerated endpoint')


def scheduler(a, folder):
    manifest = read(folder / 'manifest.json')
    cfg = manifest['config']
    if folder.name == 'scheduler':
        for key, value in dict(seed_start=220001, seeds=100, dimension=256, budget=3).items():
            a.same(cfg[key], value, 'scheduler frozen protocol '+key)
    seeds = list(range(cfg['seed_start'], cfg['seed_start'] + cfg['seeds']))
    a.check(not set(seeds).intersection(range(210001, 210004)), 'scheduler development/evaluation seed overlap')
    for name, expected in manifest['source_hashes'].items():
        a.same(sha(name), expected, 'scheduler unchanged run-start source ' + name)
    files = sorted(folder.glob('seed_*.json'))
    a.same({int(p.stem.split('_')[1]) for p in files}, set(seeds), 'scheduler seed files complete')
    independently_derived = {}
    semantic_total = 0
    for path in files:
        result = read(path)
        seed = result['seed']
        rowmap = {(r['scenario'], r['method']): r for r in result['rows']}
        a.same(len(rowmap), len(SCENARIOS) * len(METHODS), f'scheduler {seed} unique rows')
        semantic = 0
        for scenario in SCENARIOS:
            for method in METHODS:
                label = f'scheduler {seed}/{scenario}/{method}'
                trace = result['traces'][scenario][method]
                a.same([r['round'] for r in trace], list(range(1, 61)), label + ' complete rounds')
                active = detected_rounds = corrupted = detections = covered = 0
                avail_rounds = missing_rounds = missing_records = inconclusive = 0
                byte_total = request_total = 0
                first = None
                for r in trace:
                    rid, slots = r['round'], r['slots']
                    bad, unavailable = set(r['integrity_targets']), set(r['withholding_targets'])
                    a.same(len(slots), cfg['budget'], label + f' round{rid} exact budget')
                    a.same(len(set(slots)), len(slots), label + f' round{rid} unique selection')
                    a.check(all(type(c) is int and 0 <= c < 30 for c in slots), label + ' slot domain')
                    a.check(not bad.intersection(unavailable), label + ' disjoint attack sets')
                    expected_bad_n = 2 if rid >= 9 and scenario not in ('honest', 'withholding_only') else 0
                    expected_missing_n = 2 if rid >= 9 and scenario not in ('honest', 'integrity_only', 'moving_integrity') and not (scenario == 'recovery' and rid >= 33) else 0
                    a.same(len(bad), expected_bad_n, label + f' round{rid} integrity trace size')
                    a.same(len(unavailable), expected_missing_n, label + f' round{rid} availability trace size')
                    expected = {str(c): FAIL if c in bad else MISSING if c in unavailable else PASS for c in slots}
                    a.same(r['record_outcomes'], expected, label + f' round{rid} semantic map')
                    semantic += len(slots)
                    hit, miss = len(set(slots).intersection(bad)), len(set(slots).intersection(unavailable))
                    a.same(r['detected_records'], hit, label + ' record detections')
                    a.same(r['covered_records'], hit, label + ' targeted coverage')
                    a.same(r['missing_records'], miss, label + ' missing evidence observations')
                    outcome = FAIL if hit else MISSING if miss else PASS
                    a.same(r['outcome'], outcome, label + ' outcome precedence')
                    active += bool(bad)
                    corrupted += len(bad)
                    detected_rounds += bool(hit)
                    detections += hit
                    covered += hit
                    avail_rounds += bool(unavailable)
                    missing_rounds += bool(miss)
                    missing_records += miss
                    inconclusive += outcome == MISSING
                    byte_total += r['bytes']
                    request_total += r['requests']
                    if hit and first is None:
                        first = rid - 9
                derived = dict(attacked_rounds=active, integrity_tdr=detected_rounds / active if active else None,
                    record_tdr=detections / corrupted if corrupted else None,
                    coverage=covered / corrupted if corrupted else None,
                    availability_observation_rate=missing_rounds / avail_rounds if avail_rounds else None,
                    missing_finding_rounds=missing_rounds, inconclusive_only_rounds=inconclusive,
                    missed_attack_rounds=active-detected_rounds, first_detection_latency=first,
                    detection_censored=bool(active) and first is None, false_fail_rounds=0,
                    bytes=byte_total, requests=request_total, missing_requests=missing_records,
                    record_attempts=len(trace)*cfg['budget'])
                row = rowmap[scenario, method]
                for key, value in derived.items():
                    a.same(row[key], value, label + ' summary ' + key)
                independently_derived[scenario, method, seed] = derived
                if scenario == 'recovery':
                    targets = set(trace[31]['withholding_targets'])
                    recovery = {x['slot']: x for x in row['recovery']}
                    a.same(set(recovery), targets, label + ' recovered target denominator')
                    for c in targets:
                        hits = [r['round']-33 for r in trace if r['round'] >= 33 and c in r['slots']]
                        a.same(recovery[c]['latency'], min(hits) if hits else None, label + ' recovery latency')
                        a.same(recovery[c]['censor_rounds'], 28 if not hits else None, label + ' recovery censoring')
                reference = result['traces'][scenario]['uniform']
                a.same([(r['integrity_targets'], r['withholding_targets']) for r in trace],
                       [(r['integrity_targets'], r['withholding_targets']) for r in reference], label + ' matched attack trace')
        for mixed, control in (('mixed', 'integrity_only'), ('moving_mixed', 'moving_integrity')):
            a.same([r['integrity_targets'] for r in result['traces'][mixed]['uniform']],
                   [r['integrity_targets'] for r in result['traces'][control]['uniform']], 'counterfactual integrity trace')
        a.same(result['semantic_checks'], semantic, 'per-seed semantic check count')
        semantic_total += semantic
    summary = read(folder / 'summary.json')
    a.same(summary['semantic_checks'], semantic_total, 'total semantic check count')
    a.same(len(summary['rows']), len(seeds)*len(SCENARIOS)*len(METHODS), 'merged scheduler row count')
    a.same(len({(r['scenario'], r['method'], r['seed']) for r in summary['rows']}), len(summary['rows']), 'unique merged scheduler rows')
    for row in summary['rows']:
        expected = independently_derived[row['scenario'], row['method'], row['seed']]
        for key, value in expected.items():
            a.same(row[key], value, 'merged scheduler ' + key)
    for scenario in SCENARIOS:
        for left, right in (('neutral', 'uniform'), ('neutral', 'separated'), ('neutral', 'adaptive'), ('separated', 'uniform')):
            entry = summary['paired'][scenario+'/'+left+'-'+right]
            for metric in independently_derived[scenario, left, seeds[0]]:
                if metric not in entry:
                    continue
                pairs = [(independently_derived[scenario, left, s][metric], independently_derived[scenario, right, s][metric]) for s in seeds]
                values = [x-y for x, y in pairs if x is not None and y is not None]
                a.same(entry[metric]['n'], len(values), 'paired seed denominator ' + metric)
                a.same(entry[metric]['mean'], sum(values)/len(values) if values else None, 'paired mean ' + metric)
                if values and len(values) > 1:
                    ci = entry[metric]['ci']
                    a.check(len(ci) == 2 and min(values) <= ci[0] <= ci[1] <= max(values), 'CI support/order ' + metric)
            if scenario == 'mixed' and left == 'neutral' and right in ('uniform', 'separated'):
                entry = entry['primary_family_ci97_5']
                a.same(entry['confidence'], .975, 'primary family confidence')
                a.same(entry['n'], len(seeds), 'primary matched-seed n')
                a.same(entry['resamples'], 20000, 'primary bootstrap resamples')
                differences = [independently_derived[scenario, left, s]['integrity_tdr']-
                               independently_derived[scenario, right, s]['integrity_tdr'] for s in seeds]
                primary_bootstrap(a, differences, entry, 'scheduler '+left+'-'+right)
    a.sections[str(folder.name)] = dict(seed_count=len(seeds), rows=len(summary['rows']),
        semantic_checks=semantic_total, denominators='independently recomputed from all round traces',
        bootstrap='paired inputs independently recomputed; two primary 97.5% percentile CIs independently regenerated')


def dimension_subset(a, folder, reference):
    scheduler(a, folder)
    config = read(folder/'manifest.json')['config']
    a.same(config['dimension'], 6241, 'dimension validation d6241')
    a.same(config['budget'], 3, 'dimension validation b3')
    a.same(config['seed_start'], 220001, 'dimension validation fixed first seed')
    a.same(config['seeds'], 20, 'dimension validation fixed subset size')
    compare_keys = ('round', 'slots', 'integrity_targets', 'withholding_targets',
                    'outcome', 'detected_records', 'covered_records', 'missing_records', 'record_outcomes')
    paired_rounds = 0
    for seed in range(config['seed_start'], config['seed_start']+config['seeds']):
        large, small = read(folder/f'seed_{seed}.json'), read(reference/f'seed_{seed}.json')
        for scenario in SCENARIOS:
            for method in METHODS:
                left = large['traces'][scenario][method]
                right = small['traces'][scenario][method]
                a.same(len(left), len(right), 'dimension validation equal trace length')
                for x, y in zip(left, right):
                    a.same({k:x[k] for k in compare_keys}, {k:y[k] for k in compare_keys},
                           f'dimension validation matched semantics {seed}/{scenario}/{method}/{x["round"]}')
                    paired_rounds += 1
    a.sections[folder.name]['cross_dimension_paired_rounds'] = paired_rounds
    a.sections[folder.name]['interpretation'] = 'same-seed deterministic semantics/cost validation, not additional independent evidence of scheduling advantage'


def response(a, folder):
    cfg, complete = read(folder/'config.json'), read(folder/'COMPLETE.json')
    for key, value in dict(seed_start=300001, seeds=20, rounds=60).items():
        a.same(cfg[key], value, 'response frozen protocol '+key)
    for name, expected_hash in cfg['source_sha256'].items():
        a.same(sha(name), expected_hash, 'response unchanged run-start source '+name)
    for name, expected_hash in cfg['data_sha256'].items():
        a.same(sha(Path(cfg['data_dir'])/name), expected_hash, 'response unchanged input data '+name)
    rows = [json.loads(line) for line in (folder/'rows.jsonl').read_text(encoding='utf8').splitlines() if line.strip()]
    seeds = list(range(cfg['seed_start'], cfg['seed_start']+cfg['seeds']))
    expected = {(s, arm) for s in seeds for arm in ARMS}
    a.same(set(cfg['arms']), set(ARMS), 'all planned response arms')
    a.same({(r['seed'], r['arm']) for r in rows}, expected, 'response complete seed-arm matrix')
    a.same(len(rows), len(expected), 'response no duplicate rows')
    a.same(complete['completed'], len(expected), 'response completion marker count')
    a.same(complete['expected'], len(expected), 'response expected marker count')
    a.same(complete['status'], 'COMPLETED', 'response completion marker status')
    model_transition_checks = 0
    for row in rows:
        arm, total, trace = row['arm'], row['totals'], row['round_rows']
        audited, full = 'noaudit' not in arm, arm == 'drop_full_b30'
        rounds = cfg['rounds']
        a.same([r['round'] for r in trace], list(range(1, rounds+1)), 'response complete rounds')
        expected_totals = dict(attack_rounds=0, attacked_updates_applied=0, attacked_records_applied=0,
            prevented_bad_rounds=0, rejected_rounds=0, honest_rounds_rejected=0,
            discarded_training_steps=0, discarded_rows_processed=0,
            local_training_steps=0, local_rows_processed=0, audit_total_bytes=0,
            audit_requests=0, audit_missing_requests=0)
        preceding_hash = row['initial_model_sha256']
        for r in trace:
            a.same(r['previous_model_sha256'], preceding_hash, 'response continuous model-state chain')
            preceding_hash = r['applied_model_sha256']
            targets = set(r['chosen']).intersection((15, 13)) if arm != 'clean_noaudit' and 21 <= r['round'] <= 60 else set()
            a.same(set(r['attack_targets']), targets, 'application fixed attack trace')
            a.same(len(r['chosen']), 10, 'ten selected training clients')
            a.same(r['local_steps'], len(r['chosen']), 'actual local minibatch steps')
            a.same(len(r['audit_slots']), (30 if full else 3) if audited else 0, 'all-round response audit budget')
            outcome = FAIL if targets.intersection(r['audit_slots']) else PASS
            a.same(r['outcome'], outcome if audited else None, 'response semantic outcome')
            a.same(r['record_outcomes'], {str(c): FAIL if c in targets else PASS for c in r['audit_slots']}, 'response observed record labels')
            reject = bool(r['outcome'] and (r['outcome'].startswith('FAIL_') or r['outcome'] == MISSING))
            a.same(r['rejected'], reject, 'response decision uses outcome')
            if 'previous_model_sha256' in r and 'applied_model_sha256' in r:
                if reject:
                    a.same(r['previous_model_sha256'], r['applied_model_sha256'], 'rejected round retains actual model hash')
                    model_transition_checks += 1
            attacked = bool(targets)
            for key, value in dict(attack_rounds=attacked, attacked_updates_applied=attacked and not reject,
                attacked_records_applied=len(targets) if not reject else 0,
                prevented_bad_rounds=attacked and reject, rejected_rounds=reject,
                honest_rounds_rejected=not attacked and reject,
                discarded_training_steps=r['local_steps'] if reject else 0,
                discarded_rows_processed=r['trained_rows'] if reject else 0,
                local_training_steps=r['local_steps'], local_rows_processed=r['trained_rows'],
                audit_total_bytes=r['audit_bytes'], audit_requests=r['audit_requests'],
                audit_missing_requests=r['missing_requests']).items():
                expected_totals[key] += value
        a.same(preceding_hash, row['final_model_sha256'], 'response last applied model equals final model')
        for key, value in expected_totals.items():
            a.same(total[key], value, f'response {row["seed"]}/{arm} '+key)
        a.same(total['audit_total_bytes'], total['audit_request_bytes']+total['audit_response_payload_bytes']+total['audit_response_framing_bytes'], 'response byte components sum')
        a.same(total['audit_calls'], rounds if audited else 0, 'response audits every round')
        a.same(total['full_audit_calls'], rounds if full else 0, 'response full calls')
        a.same(total['actual_replays'], rounds-total['rejected_rounds'] if full else 0, 'response replay only after no local failures')
        a.same(total['aggregate_verified'], total['actual_replays'], 'response aggregate verification scope')
        a.same(total['application_upload_payload_bytes'], rounds*10*row['dimension']*8, 'all training uploads including discarded rounds')
        a.same(total['application_download_payload_bytes'], rounds*10*row['dimension']*8, 'all model broadcasts including discarded rounds')
        a.same(total['candidate_download_payload_bytes'], rounds*row['dimension']*8, 'all candidate downloads')
        a.same(total['response_extra_payload_bytes'], 0, 'no retransmission/replacement response')
    bykey = {(r['seed'], r['arm']): r for r in rows}
    for seed in seeds:
        part = [bykey[seed, arm] for arm in ARMS]
        a.same(len({r['initial_model_sha256'] for r in part}), 1, 'matched initial models')
        a.same(len({r['selection_schedule_sha256'] for r in part}), 1, 'matched client schedules')
        neutral, separated = bykey[seed, 'drop_neutral_b3'], bykey[seed, 'drop_separated_b3']
        a.same(neutral['final_model_sha256'], separated['final_model_sha256'], 'no missing observations means neutral/separated same model')
        a.same(neutral['final'], separated['final'], 'no missing observations means neutral/separated same utility')
        a.same(neutral['round_rows'], separated['round_rows'], 'no missing observations means neutral/separated same trace')
    summary = read(folder/'summary.json')
    a.same(summary['n_runs'], len(rows), 'response analyzed run count')
    a.same(summary['n_seeds'], len(seeds), 'response analyzed seed count')
    for arm in ARMS:
        part = [bykey[seed, arm] for seed in seeds]
        for metric, entry in summary['means'][arm].items():
            if not isinstance(entry, dict) or 'mean' not in entry:
                continue
            values = [r['final'][metric] if metric in r['final'] else r['totals'][metric] for r in part]
            a.same(entry['n'], len(values), 'response analyzed metric denominator')
            a.same(entry['mean'], sum(values)/len(values), 'response independently recomputed mean '+metric)
    for name, entries in summary['paired'].items():
        left, right = name.split('-')
        for metric, entry in entries.items():
            if metric == 'primary_f1_ci97_5':
                metric = 'f1'
                a.same(entry['confidence'], .975, 'response primary confidence')
            values = []
            for seed in seeds:
                x, y = bykey[seed, left], bykey[seed, right]
                block = 'final' if metric in x['final'] else 'totals'
                values.append(x[block][metric]-y[block][metric])
            a.same(entry['n'], len(values), 'response paired denominator')
            a.same(entry['mean'], sum(values)/len(values), 'response paired mean '+metric)
            if metric == 'f1' and entry.get('confidence') == .975:
                primary_bootstrap(a, values, entry, 'response '+name)
    a.sections['response'] = dict(rows=len(rows), seeds=len(seeds),
        rejected_model_hash_checks=model_transition_checks,
        model_retention_evidence='hash-checked rejected transitions' if model_transition_checks else 'decision/counter checks only; actual model retention also requires source/test evidence')


def preservation(a, project):
    frozen = project/'submission_v4/experiments/pba_v2/results/release_v4'
    manifest = read(frozen/'reproducibility_manifest.json')
    for name, info in manifest['artifacts'].items():
        path = frozen/name
        a.same(path.stat().st_size, info['bytes'], 'frozen artifact size '+name)
        a.same(sha(path), info['sha256'], 'frozen artifact hash '+name)
    tex, pdf = (project/'submission_v4'/('policy_bound_edge_ids_v2.'+ext) for ext in ('tex', 'pdf'))
    a.same(sha(tex), '7b1b3b63c7582b37aeb707d4cbb17acaa691ddf8c27ec4fee7b2c4ec59ff2a1d', 'initial manuscript TeX preserved')
    a.same(sha(pdf), '06aa5093a7ea831e6ccd0b6ce11add51d57c870bd70a5982282ca5340e1989bb', 'initial current PDF preserved')
    a.sections['preservation'] = dict(frozen_entries=len(manifest['artifacts']), tex_sha256=sha(tex), pdf_sha256=sha(pdf))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    audit = Audit()
    for label, function in [('scheduler', lambda: scheduler(audit, root/'scheduler')),
                            ('scheduler_d6241', lambda: dimension_subset(audit, root/'scheduler_d6241', root/'scheduler')),
                            ('response', lambda: response(audit, root/'response')),
                            ('preservation', lambda: preservation(audit, Path(__file__).resolve().parents[2]))]:
        try:
            function()
        except Exception as exc:
            audit.errors.append(label+': '+repr(exc))
    result = dict(status='PASS' if not audit.errors else 'FAIL', checks=audit.checks,
        errors=audit.errors, sections=audit.sections,
        scope='Independent stored-output recomputation and preservation checks, not a full rerun or paper-validity certificate.')
    (root/'validation.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if audit.errors else 0


if __name__ == '__main__':
    sys.exit(main())
