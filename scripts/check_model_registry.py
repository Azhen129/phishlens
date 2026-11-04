"""Validate every present trusted bundle and explicitly report optional omissions.

An absent optional artifact can select clearly identified rules-only CI. A
present artifact that fails loading/integrity checks always fails this check;
it must never silently downgrade the verification mode.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend import ml_runtime


def check_registry() -> dict:
    ml_runtime.clear_cache()
    statuses, errors = {}, []
    for kind in ml_runtime.MODEL_SPECS:
        try:
            directory = ml_runtime._model_directory(kind)
        except (OSError, ValueError, TypeError):
            statuses[kind] = {'state': 'invalid_selection', 'available': False}
            errors.append(kind)
            continue
        artifact = directory/'model.joblib'
        if not artifact.exists():
            # Public source may intentionally retain model cards/metadata while
            # omitting optional weights. Malformed present metadata is still a
            # failure, not an excuse to downgrade a broken bundle silently.
            try:
                metadata = {}
                for name, limit in (('manifest.json',2*1024*1024), ('metrics.json',16*1024*1024)):
                    path = directory/name
                    if path.exists():
                        metadata[name] = ml_runtime._json_file(path, limit=limit)
                if metadata:
                    manifest=metadata.get('manifest.json',{})
                    metrics=metadata.get('metrics.json',{})
                    expected_kind=ml_runtime.MODEL_SPECS[kind][0]
                    if (set(metadata)!={'manifest.json','metrics.json'}
                        or manifest.get('format_version')!=1
                        or manifest.get('kind')!=expected_kind
                        or manifest.get('artifact')!='model.joblib'
                        or manifest.get('metrics_file')!='metrics.json'
                        or not isinstance(manifest.get('version'),str)
                        or not re.fullmatch(r'[a-fA-F0-9]{64}',str(manifest.get('sha256','')))
                        or metrics.get('kind')!=expected_kind
                        or metrics.get('version')!=manifest.get('version')):
                        raise ValueError('Incomplete or mismatched optional model metadata.')
            except (OSError, ValueError, TypeError):
                statuses[kind] = {'state': 'invalid_present_metadata', 'available': False}
                errors.append(kind)
                continue
            statuses[kind] = {'state': 'optional_weights_absent', 'available': False}
            continue
        bundle, _ = ml_runtime._load(kind)
        if bundle is None:
            statuses[kind] = {'state': 'present_bundle_failed_integrity_or_loading', 'available': False}
            errors.append(kind)
        else:
            statuses[kind] = {'state': 'trusted_bundle_loaded', 'available': True, 'version': bundle['version'], 'artifact_sha256': bundle['artifact_sha256']}
    complete = not errors and all(value['available'] for value in statuses.values())
    mode='invalid_registry' if errors else 'full_trusted_models' if complete else 'explicit_rules_only_ci'
    return {'format_version':1, 'passed':not errors, 'full_registry':complete, 'mode':mode, 'models':statuses, 'failed_model_keys':errors, 'coverage_notice':'Full backend and trained-model browser workflows are required.' if complete else 'Optional learned-model workflow checks are NOT RUN in this CI mode; rules-only checks do not establish trained-model compatibility or accuracy.'}


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'work/phase6/model-registry-check.json')
    parser.add_argument('--github-output',type=Path)
    args=parser.parse_args()
    result=check_registry()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    if args.github_output:
        with args.github_output.open('a',encoding='utf-8') as stream:
            stream.write('full_registry='+str(result['full_registry']).lower()+'\n')
    print(json.dumps(result,indent=2))
    return 0 if result['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
