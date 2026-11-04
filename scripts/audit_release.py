"""Read-only release inventory with redacted findings and an explicit review policy.

This is a bounded pattern scan, not a guarantee that a repository contains no
secrets or personal data. It never changes a source file or deserializes models.
Use --root for an already staged public tree and --strict-public to fail on
unresolved path/data/model/reference review as well as credential findings.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_TEXT_BYTES = 32 * 1024 * 1024
BINARY_SUFFIXES = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf', '.zip', '.gz', '.bz2', '.xz', '.7z', '.joblib', '.pkl', '.pickle', '.woff', '.woff2', '.ttf'}
PRIVATE_PARTS = {'.git', '.venv', 'node_modules', 'work', 'outputs', 'dist', 'test-results', 'playwright-report', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', '.cache'}
SYNTHETIC_MAIL = {'fixtures/ordinary-update.eml', 'fixtures/suspicious-invoice.eml', 'fixtures/spanish-account-review.eml'}
PERSONAL_PATH = re.compile(r'(?i)(?:[a-z]:[\\/]+Users[\\/]+[^\s"\'<>]+|/(?:Users|home)/[^\s"\'<>]+)')
SECRET_PATTERNS = {
    'github_token': re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,}\b'),
    'github_fine_grained_token': re.compile(r'\bgithub_pat_[A-Za-z0-9_]{40,}\b'),
    'aws_access_key_id': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'private_key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'openai_like_key': re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b'),
}


def public_action(name: str) -> tuple[str, str]:
    """Policy decisions do not establish ownership, licensing or privacy clearance."""
    p = Path(name)
    if PRIVATE_PARTS.intersection(p.parts) or name.startswith(('backend/data/', 'data/raw/', 'datasets/')):
        return 'exclude', 'private data, dependency, backup or generated workspace content'
    if p.name == '.env' or (p.name.startswith('.env.') and p.name != '.env.example'):
        return 'exclude', 'environment configuration may contain private values'
    if p.suffix.lower() in {'.sqlite3', '.db', '.mbox', '.pst', '.ost', '.pem', '.key', '.p12', '.pfx'} or '.sqlite3-' in p.name:
        return 'exclude', 'database, raw mailbox or private key container'
    if p.suffix.lower() in {'.eml', '.msg'} and name not in SYNTHETIC_MAIL:
        return 'exclude', 'unreviewed email content'
    if p.suffix.lower() in {'.csv', '.tsv', '.parquet', '.arrow'}:
        return 'exclude', 'raw/prepared corpus data is not a source deliverable'
    if name.startswith('design-references/'):
        return 'manual_rights_review', 'supplied reference-image redistribution rights are unresolved'
    if name.startswith('backend/models/') and p.suffix.lower() in {'.joblib', '.pkl', '.pickle'}:
        return 'manual_model_review', 'trusted executable serialization; review provenance, attribution and artifact scope before any public distribution'
    if name in {'docs/CODEX_MASTER_PROMPT.md', 'docs/PHASE3_REQUEST.md'}:
        return 'exclude_from_public_copy', 'conversation/request material is unnecessary for running the portfolio project'
    return 'candidate', 'source, documentation or explicitly named synthetic software fixture'


def candidate_names(root: Path, *, use_git: bool = True) -> list[str]:
    if use_git and (root/'.git').exists():
        raw = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root)
        return sorted(set(filter(None, raw.decode('utf-8').split('\0'))))
    return sorted(p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and not PRIVATE_PARTS.intersection(p.relative_to(root).parts))


def audit(root: Path, names: list[str]) -> dict:
    root = root.resolve()
    inventory, findings = [], []
    for name in sorted(set(names)):
        path = root/name
        if not path.resolve().is_relative_to(root):
            findings.append({'path': name, 'category': 'outside_root', 'severity': 'block', 'detail': 'Path resolves outside the intended release tree.'})
            continue
        if not path.is_file():
            continue
        action, rationale = public_action(name)
        data = path.read_bytes()
        item = {'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'public_action': action, 'rationale': rationale}
        inventory.append(item)
        if action == 'exclude':
            findings.append({'path': name, 'category': 'private_or_generated_file', 'severity': 'block', 'detail': rationale})
        elif action.startswith('manual_'):
            findings.append({'path': name, 'category': action, 'severity': 'review', 'detail': rationale})
        if path.suffix.lower() in BINARY_SUFFIXES:
            item['text_scan'] = 'not_text; never deserialized or opened as active content'
            continue
        if len(data) > MAX_TEXT_BYTES:
            item['text_scan'] = 'skipped; exceeds bounded text scan'
            findings.append({'path': name, 'category': 'unscanned_large_text', 'severity': 'review', 'detail': 'Manual review needed; do not treat an unscanned file as clean.'})
            continue
        try:
            content = data.decode('utf-8-sig')
        except UnicodeDecodeError:
            item['text_scan'] = 'not_utf8; manual review if publicly included'
            findings.append({'path': name, 'category': 'unscanned_encoding', 'severity': 'review', 'detail': 'Cannot inspect as UTF-8 text.'})
            continue
        item['text_scan'] = 'bounded UTF-8 pattern scan completed'
        if name in SYNTHETIC_MAIL and '[DEV FIXTURE]' not in content:
            findings.append({'path': name, 'category': 'fixture_marker_missing', 'severity': 'block', 'detail': 'A reviewed synthetic fixture path lost its explicit development marker; inspect its contents privately before release.'})
        for line_number, line in enumerate(content.splitlines(), 1):
            if PERSONAL_PATH.search(line):
                findings.append({'path': name, 'line': line_number, 'category': 'personal_absolute_path', 'severity': 'review', 'detail': 'Retain original forensic evidence locally; sanitize only an explicitly identified public copy and record both hashes.'})
                if item['public_action'] == 'candidate':
                    item['public_action'] = 'copy_with_redaction'
            for label, pattern in SECRET_PATTERNS.items():
                if pattern.search(line):
                    findings.append({'path': name, 'line': line_number, 'category': label, 'severity': 'block', 'detail': 'Potential credential format matched. Matched values are deliberately omitted.'})
    counts = Counter(f['category'] for f in findings)
    blockers = sum(f['severity'] == 'block' for f in findings)
    review = sum(f['severity'] == 'review' for f in findings)
    return {
        'format_version': 1,
        'scope': 'Current candidate tree only; not Git history, OS caches, external services, model contents or complete secret detection.',
        'files_scanned': len(inventory),
        'blocking_findings': blockers,
        'review_findings': review,
        'category_counts': dict(sorted(counts.items())),
        'no_credential_pattern_matches': not any(k in SECRET_PATTERNS for k in counts),
        'public_release_cleared': False,
        'owner_decisions_pending': ['Project source license has not been granted in LICENSE.NOTICE.md.', 'Supplied design-reference images need a distribution-rights decision; exclude from conservative public copy.', 'Final artifact/model inclusion and publication require the owner review requested for Phase 6.'],
        'findings': findings,
        'inventory': inventory,
        'policy': {'preserve_originals': True, 'redact_in_place': False, 'raw_corpora_or_user_sqlite_distributed': False, 'model_hashes_change_during_sanitization': False, 'fixture_mail': sorted(SYNTHETIC_MAIL)},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, default=ROOT/'docs/ml/phase6/release-audit.json')
    parser.add_argument('--strict-public', action='store_true', help='Fail on unresolved review items; this does not grant publication permission.')
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output.resolve()
    names = [name for name in candidate_names(root) if (root/name).resolve() != output]
    result = audit(root, names)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('files_scanned', 'blocking_findings', 'review_findings', 'no_credential_pattern_matches', 'public_release_cleared')}, indent=2))
    return 1 if result['blocking_findings'] or (args.strict_public and (result['review_findings'] or result['owner_decisions_pending'])) else 0


if __name__ == '__main__':
    raise SystemExit(main())
