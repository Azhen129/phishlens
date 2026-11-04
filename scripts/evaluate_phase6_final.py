"""Score the frozen Phase 6 holdout once, using fixed versions and thresholds."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import sklearn
from threadpoolctl import threadpool_limits

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.analysis import inspect_email
from backend.language_routing_v2 import route_email_language as route_v2
from backend.language_routing_v3 import route_email_language as route_v3
from backend.ml_runtime import _classify_language, _load
from backend.ml_training import sha256_file
from backend.ml_training_v6 import metric_report
from backend.text_normalization_v6 import normalize_english_text
from scripts.evaluate_phase5_final import full_predictions, paired, predict, route_summary, selected_score

REPORTS = ROOT / 'docs/ml/phase6'
RAW = ROOT / 'work/phase6/raw'


def load_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def offline_model(spec, stage):
    """Read only known project-owned research bundles with frozen identities."""
    pattern = r'email_en_v5/email-multiscale-v3-[a-f0-9]{12}' if stage == 5 else r'email_en_v6/email-source-text-v6-[a-f0-9]{12}'
    relative = spec['directory'].removeprefix('backend/models/')
    if not re.fullmatch(pattern, relative):
        raise ValueError('Unexpected frozen research model location.')
    directory = ROOT / 'backend/models' / relative
    artifact = directory / 'model.joblib'
    if artifact.resolve() != artifact or not 0 < artifact.stat().st_size <= 64 * 1024 * 1024:
        raise ValueError('Unexpected research artifact path or size.')
    original_manifest = directory / 'manifest.pre-admission.json'
    manifest = load_json(original_manifest if original_manifest.is_file() else directory / 'manifest.json')
    metadata = manifest['metadata']
    additional = 'ml_features_v3.py' if stage == 5 else 'text_normalization_v6.py'
    assert manifest['validated'] is False
    assert manifest['kind'] == 'email' and manifest['sklearn_version'] == sklearn.__version__
    assert manifest['version'] == spec['version'] == directory.name
    assert manifest['artifact'] == 'model.joblib' and metadata['supported_languages'] == ['en']
    assert sha256_file(artifact) == manifest['sha256'] == spec['model_sha256']
    assert sha256_file(ROOT / 'backend/ml_features.py') == metadata['feature_code_sha256']
    assert metadata['additional_code_sha256'] == {additional: sha256_file(ROOT / 'backend' / additional)}
    bundle = joblib.load(artifact)
    assert bundle['kind'] == 'email' and bundle['version'] == spec['version']
    assert bundle['threshold'] == spec['threshold']
    return bundle, directory


def read_rows(path):
    with path.open(encoding='utf-8', newline='') as stream:
        return list(csv.DictReader(stream))


def evaluate(output):
    if output.exists():
        raise ValueError('Final report already exists. Preserve the original result.')
    selection = load_json(REPORTS / 'selection.json')
    provenance = load_json(REPORTS / 'provenance.json')
    preparation = load_json(REPORTS / 'preparation-audit.json')
    assert selection['all_three_artifacts_frozen_before_final'] and not selection['final_data_read']
    assert sha256_file(REPORTS / 'provenance.json') == selection['provenance_sha256']
    assert sha256_file(RAW / 'development.csv') == selection['dataset_sha256'] == provenance['prepared']['sha256']
    assert sha256_file(RAW / 'final.csv') == provenance['final']['sha256']
    assert sha256_file(REPORTS / 'preparation-audit.json') == provenance['preparation_audit_sha256']
    assert preparation['development_final_group_intersection'] == preparation['final_previously_observed_group_intersection'] == 0
    assert all(sha256_file(ROOT / path) == digest for path, digest in selection['code_sha256'].items())

    baseline, reason = _load('email_en', use_active=False)
    assert baseline is not None, reason
    spanish, reason = _load('email', use_active=False)
    assert spanish is not None, reason
    phase5, directory = offline_model(load_json(ROOT / 'docs/ml/phase5/selection.json'), 5)
    bundles = {'baseline': baseline, 'phase5_rejected': phase5}
    watched_dirs = [directory, ROOT / 'backend/models/email', ROOT / 'backend/models/email_en']
    for name, spec in selection['candidates'].items():
        bundles[name], directory = offline_model(spec, 6)
        watched_dirs.append(directory)

    watched = [RAW / 'development.csv', RAW / 'final.csv', REPORTS / 'selection.json', REPORTS / 'provenance.json']
    watched += [ROOT / path for path in ('backend/analysis.py', 'backend/ml_runtime.py', 'backend/language_routing_v2.py', 'backend/language_routing_v3.py', 'backend/ml_features.py', 'backend/ml_features_v3.py', 'backend/text_normalization_v6.py')]
    watched += [path for directory in watched_dirs for path in directory.iterdir() if path.is_file()]
    identities = {path.relative_to(ROOT).as_posix(): sha256_file(path) for path in watched}

    csv.field_size_limit(2 * 1024 * 1024)
    rows = read_rows(RAW / 'final.csv')
    development = read_rows(RAW / 'development.csv')
    assert len(rows) == provenance['final']['rows']
    assert {row['role'] for row in rows} == {'final'}
    for key in ('row_id', 'group'):
        assert not {row[key] for row in rows} & {row[key] for row in development}
    assert len({row['row_id'] for row in rows}) == len(rows)
    y = np.asarray([int(row['label']) for row in rows])
    groups = np.asarray([row['group'] for row in rows])
    sources = np.asarray([row['source'] for row in rows])
    parsed, points, old_routes, new_routes = [], [], [], []
    for i, row in enumerate(rows, 1):
        scan = inspect_email(row['text'], use_ml=False)
        value = 'Subject: ' + scan['subject'] + '\n\n' + scan['email']['body']
        parsed.append(value)
        points.append(scan['score'])
        old_routes.append(route_v2(value, _classify_language))
        new_routes.append(route_v3(value, _classify_language))
        if i % 1000 == 0:
            print(f'Parsed and routed {i:,}/{len(rows):,} held-out messages.', flush=True)
    points = np.asarray(points)
    spanish_scores = predict(spanish['model'], parsed)
    models = {}
    for name, bundle in bundles.items():
        _, scores, threshold = selected_score(bundle, parsed, points)
        models[name] = {'version': bundle['version'], 'threshold': threshold, 'scores': scores,
                        'v2': full_predictions(old_routes, scores, threshold, spanish_scores, spanish['threshold'], points),
                        'v3': full_predictions(new_routes, scores, threshold, spanish_scores, spanish['threshold'], points)}
        print(f'Scored fixed {name}.', flush=True)

    ham = sources == 'MeAJOR-trec7'
    subsets = {'primary': ham | (sources == 'PhishingPot-strict_phishing'),
               'historical_nazario_2019': ham | (sources == 'Nazario-2019'),
               'broader_financial_scam': ham | (sources == 'PhishingPot-financial_scam'),
               'all_labels_descriptive': np.ones(len(rows), dtype=bool)}
    subsets.update({'source:' + source: sources == source for source in sorted(set(sources))})

    def metrics(mask, scores, threshold, decision=False):
        result = metric_report(y[mask], scores[mask], threshold, groups=groups[mask], sources=sources[mask], bootstrap=True, calibrated=not decision)
        if decision:
            for key in ('roc_auc', 'average_precision', 'pr_auc_trapezoid', 'brier_score', 'log_loss', 'expected_calibration_error'):
                result[key] = None
            result['curves'] = {}
        return result

    reports = {}
    for name, mask in subsets.items():
        reports[name] = {'n': int(mask.sum()), 'groups': len(set(groups[mask])), 'source_counts': dict(Counter(sources[mask])),
                         'router_v2': route_summary([old_routes[i] for i in np.flatnonzero(mask)], y[mask]),
                         'router_v3': route_summary([new_routes[i] for i in np.flatnonzero(mask)], y[mask]),
                         'heuristic_high': metrics(mask, points >= 60, .5, decision=True),
                         'heuristic_review': metrics(mask, points >= 25, .5, decision=True), 'models': {}}
        for key, entry in models.items():
            reports[name]['models'][key] = {'model_only': metrics(mask, entry['scores'], entry['threshold']),
                'pipeline_v2': metrics(mask, entry['v2'], .5, decision=True),
                'pipeline_v3': metrics(mask, entry['v3'], .5, decision=True),
                'paired_against_baseline_v3': paired(y[mask], models['baseline']['v3'][mask], entry['v3'][mask])}
    chosen = selection['selected_candidate']
    primary = reports['primary']['models']
    old = primary['baseline']['pipeline_v3']
    new = primary[chosen]['pipeline_v3']
    conditions = {'validation_constraints_met': selection['primary_eligible_for_independent_admission'],
                  'primary_recall_gain_at_least_5pp': new['recall'] >= old['recall'] + .05,
                  'primary_fpr_at_most_1pct': new['false_positive_rate'] <= .01,
                  'primary_wilson_upper_fpr_at_most_2pct': new['wilson_95']['false_positive_rate'][1] <= .02,
                  'fpr_increase_at_most_half_percentage_point': new['false_positive_rate'] <= old['false_positive_rate'] + .005}
    for name, report in reports.items():
        if not name.startswith('source:'):
            continue
        result = report['models'][chosen]['pipeline_v3']
        if int(result['class_balance']['0']) >= 200:
            conditions[name + ':fpr_bounds'] = result['false_positive_rate'] <= .01 and result['wilson_95']['false_positive_rate'][1] <= .02
    result = {'selected_candidate': chosen, 'admission_conditions': conditions, 'statistical_admission_passed': all(conditions.values()),
              'identities': identities, 'models': {k: {'version': v['version'], 'threshold': v['threshold']} for k, v in models.items()},
              'metrics': reports, 'no_fitting_or_threshold_selection': True,
              'records': [{'sha256': row['row_id'], 'group_sha256': row['group'], 'source': row['source'], 'label': int(row['label']),
                  'normalized_length': len(normalize_english_text(row['text'])), 'rule_points': int(points[i]),
                  'routes': {k: [route['detected_language'], route['language_routing_status']] for k, route in [('v2', old_routes[i]), ('v3', new_routes[i])]},
                  'models': {k: {'decision_score': float(v['scores'][i]), 'pipeline_v2_high': bool(v['v2'][i]), 'pipeline_v3_high': bool(v['v3'][i])} for k, v in models.items()}}
                  for i, row in enumerate(rows)]}
    assert all(sha256_file(ROOT / path) == digest for path, digest in identities.items())
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'admission_conditions': conditions, 'primary': {k: {n: v['pipeline_v3'][n] for n in ('confusion_matrix', 'recall', 'false_positive_rate', 'f1')} for k, v in primary.items()}}, indent=2), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=REPORTS / 'independent-evaluation.json')
    with threadpool_limits(limits=1):
        evaluate(parser.parse_args().out)
