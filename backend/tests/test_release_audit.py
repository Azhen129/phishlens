"""Public-copy inventory catches concrete leaks without echoing their contents."""
import json

from scripts.audit_release import audit, public_action


def test_audit_reports_credential_location_without_exposing_value(tmp_path):
    secret = 'gh' + 'p_' + 'x' * 36
    (tmp_path/'settings.txt').write_text('TOKEN=' + secret)
    result = audit(tmp_path, ['settings.txt'])
    assert result['blocking_findings'] == 1
    assert result['findings'][0]['category'] == 'github_token'
    assert result['findings'][0]['line'] == 1
    assert secret not in json.dumps(result)
    assert not result['no_credential_pattern_matches']


def test_personal_path_needs_public_copy_redaction_without_mutating_source(tmp_path):
    private_path = 'C:' + '/' + 'Users' + '/example-operator/project'
    path = tmp_path/'report.md'
    original = 'Original local run: ' + private_path
    path.write_text(original)
    result = audit(tmp_path, ['report.md'])
    assert result['review_findings'] == 1
    assert result['inventory'][0]['public_action'] == 'copy_with_redaction'
    assert private_path not in json.dumps(result)
    assert path.read_text() == original
    assert result['public_release_cleared'] is False


def test_raw_mail_data_and_unreviewed_weights_are_never_automatically_cleared():
    for name in ('inbox.eml', 'archive.mbox', 'emails.csv', 'backend/data/phishlens.sqlite3', '.env'):
        assert public_action(name)[0] == 'exclude'
    assert public_action('fixtures/ordinary-update.eml')[0] == 'candidate'
    assert public_action('backend/models/email/model.joblib')[0] == 'manual_model_review'
    assert public_action('design-references/01-dashboard.png')[0] == 'manual_rights_review'


def test_known_fixture_filename_cannot_silently_lose_its_development_marker(tmp_path):
    path = tmp_path/'fixtures'
    path.mkdir()
    (path/'ordinary-update.eml').write_text('Subject: Actual private mail\n\nNot a fixture.')
    result = audit(tmp_path, ['fixtures/ordinary-update.eml'])
    assert result['blocking_findings'] == 1
    assert result['findings'][0]['category'] == 'fixture_marker_missing'
