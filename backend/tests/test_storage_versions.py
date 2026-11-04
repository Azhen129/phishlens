"""Persistence must refuse future schemas without rewriting their version/data."""
import sqlite3
from pathlib import Path
import pytest
from backend import storage
from backend.main import _isolated_test_mode


def test_future_database_schema_remains_unchanged(tmp_path, monkeypatch):
    path=tmp_path/'future.sqlite3'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE records(kind TEXT,id TEXT,data TEXT,PRIMARY KEY(kind,id))')
        db.execute("INSERT INTO records VALUES ('analysis','kept','private preserved data')")
        db.execute('PRAGMA user_version=7')
    before=path.read_bytes()
    monkeypatch.setenv('PHISHLENS_DB',str(path))
    with pytest.raises(RuntimeError,match='Unsupported database schema'):
        storage.get('analysis','kept')
    assert path.read_bytes()==before
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==7
        assert db.execute('SELECT data FROM records').fetchone()[0]=='private preserved data'


@pytest.mark.parametrize('initial_version',[0,1])
def test_current_or_legacy_database_preserves_records(tmp_path,monkeypatch,initial_version):
    path=tmp_path/'existing.sqlite3'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE records(kind TEXT,id TEXT,data TEXT,PRIMARY KEY(kind,id))')
        db.execute('INSERT INTO records VALUES (?,?,?)',('investigation','case','{"id":"case","notes":"retained","status":"In Review"}'))
        db.execute(f'PRAGMA user_version={initial_version}')
    monkeypatch.setenv('PHISHLENS_DB',str(path))
    assert storage.get('investigation','case')=={'id':'case','notes':'retained','status':'In Review'}
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==1


def test_qa_flag_requires_the_designated_isolated_database(monkeypatch, tmp_path):
    monkeypatch.setenv('PHISHLENS_TEST_MODE', '1')
    monkeypatch.delenv('PHISHLENS_DB', raising=False)
    assert not _isolated_test_mode()
    monkeypatch.setenv('PHISHLENS_DB', str(tmp_path / 'analyst.sqlite3'))
    assert not _isolated_test_mode()
    root = Path(__file__).resolve().parents[2]
    monkeypatch.setenv('PHISHLENS_DB', str(root / 'work/phase6/e2e.sqlite3'))
    assert _isolated_test_mode()
    monkeypatch.delenv('PHISHLENS_TEST_MODE')
    assert not _isolated_test_mode()
