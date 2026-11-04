"""Fetch fixed licensed data snapshots only; never follow URLs inside messages."""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
import ssl
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
POT_COMMIT = '80a486701223f31e5c641024d6e45f2663f1b2cb'
ALLOWED = {'api.github.com', 'raw.githubusercontent.com', 'zenodo.org', 'www.monkey.org', 'monkey.org'}
HEADERS = {'User-Agent': 'PhishLens-offline-noncommercial-research/phase6'}

def checked(url):
    p = urlsplit(url)
    if p.scheme != 'https' or p.hostname not in ALLOWED or p.username or p.password:
        raise ValueError('Acquisition URL/redirect outside reviewed repository hosts.')

class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        checked(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def fetch(url, path, limit, *, md5=None, blob=None, size=None, sha256=None):
    checked(url)
    def valid(data):
        return ((size is None or len(data) == size)
                and (md5 is None or hashlib.md5(data).hexdigest() == md5)
                and (sha256 is None or hashlib.sha256(data).hexdigest() == sha256)
                and (blob is None or hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() == blob))
    if path.exists():
        data = path.read_bytes()
        if not valid(data):
            raise ValueError('Existing snapshot differs from pinned identity.')
        return data
    opener = urllib.request.build_opener(Redirects(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(urllib.request.Request(url, headers=HEADERS), timeout=60) as response:
        checked(response.url)
        data = response.read(limit+1)
        if len(data) > limit or not valid(data):
            raise ValueError('Snapshot checksum/size mismatch; review without bypassing checks.')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data)
    return data

def acquire(output):
    output.mkdir(parents=True, exist_ok=True)
    card_url = f'https://raw.githubusercontent.com/rf-peixoto/phishing_pot/{POT_COMMIT}/DATASET_CARD.md'
    card = fetch(card_url, output/'pot-DATASET_CARD.md', 100_000)
    license_data = fetch(f'https://raw.githubusercontent.com/rf-peixoto/phishing_pot/{POT_COMMIT}/LICENSE', output/'pot-LICENSE', 100_000)
    if b'CC BY-NC 4.0' not in card or b'NonCommercial' not in license_data:
        raise ValueError('Reviewed explicit noncommercial data permission missing.')
    tree_url = f'https://api.github.com/repos/rf-peixoto/phishing_pot/git/trees/{POT_COMMIT}?recursive=1'
    tree = json.loads(fetch(tree_url, output/'pot-tree.json', 8_000_000))
    if tree.get('truncated'):
        raise ValueError('Repository tree was truncated.')
    eligible = [r for r in tree['tree'] if r['type']=='blob' and r['path'].startswith('email/') and r['path'].endswith('.eml') and 0 < r.get('size',0) <= 1_000_000]
    # Fixed before content review or scores; no outcome/language keyword sampling.
    selected = sorted(eligible, key=lambda r: hashlib.sha256((POT_COMMIT+'/'+r['path']).encode()).hexdigest())[:400]
    def download(row):
        url = f'https://raw.githubusercontent.com/rf-peixoto/phishing_pot/{POT_COMMIT}/'+row['path']
        data = fetch(url, output/'pot'/Path(row['path']).name, 1_000_000, blob=row['sha'], size=row['size'])
        return {'path': row['path'], 'blob_sha1': row['sha'], 'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest(), 'url':url}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        pot_files = list(pool.map(download, selected))
    zenodo_url = 'https://zenodo.org/api/records/18471483'
    zenodo = json.loads(fetch(zenodo_url, output/'meajor-metadata.json', 100_000))
    if zenodo['metadata']['license']['id'] != 'cc-by-4.0':
        raise ValueError('Reviewed curator permission differs.')
    name = 'meajor_cleaned_preprocessed.csv'
    spec = next(r for r in zenodo['files'] if r['key']==name)
    if spec['checksum'] != 'md5:aa8f59e96787cbd696c0b650e5400dc9' or spec['size'] != 191121228:
        raise ValueError('Reviewed release changed.')
    data = fetch(spec['links']['self'], output/name, 200_000_000, md5=spec['checksum'][4:], size=spec['size'])
    report = {'phase':6,'pot_commit':POT_COMMIT,'pot_license':'CC BY-NC 4.0; final local noncommercial evaluation only, never fitted or redistributed', 'pot_eligible_messages_under_1MB':len(eligible),'pot_prespecified_sample_size':len(pot_files),'pot_sampling':'First 400 commit/path SHA256 order, before content/labels/model scores; 1MB bound', 'pot_card_sha256':hashlib.sha256(card).hexdigest(),'pot_license_sha256':hashlib.sha256(license_data).hexdigest(),'pot_files':pot_files,'meajor':{'url':spec['links']['self'],'doi':'10.5281/zenodo.18471483','license':'CC BY 4.0 curator release; original source/sender rights inherited','bytes':len(data),'md5':spec['checksum'][4:],'sha256':hashlib.sha256(data).hexdigest(),'use':'Only benign0 rows; all merged spam/phishing positives excluded; source roles fixed before final scoring'},'security':'Fixed repository hosts and checked redirects; pinned Git blobs/publisher checksum. No contained URL, HTML, script or attachment is executed.'}
    nazario_url='https://www.monkey.org/~jose/phishing/phishing-2019'
    nazario=fetch(nazario_url, output/'nazario-phishing-2019.mbox', 6_000_000, size=5211476, sha256='cab39d6fcb38cf80cdaabb3e6ffd1222777e2fcaac7e8480321b7f729c2e3c0e')
    report['nazario_2019']={'url':nazario_url,'sha256':hashlib.sha256(nazario).hexdigest(),'bytes':len(nazario),'raw_messages':243,'license':'Author CC BY 4.0','role':'Unused messages, supplementary final strict-phishing stress; same curator as training, not an independent curator or future-time test'}
    path = output/'acquisition-v2.json'
    serialized = json.dumps(report, indent=2)+'\n'
    if path.exists() and path.read_text() != serialized:
        raise ValueError('Refusing to replace differing acquisition evidence.')
    path.write_text(serialized, encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k != 'pot_files'}, indent=2), flush=True)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, default=ROOT/'work/phase6/raw')
    args=p.parse_args()
    acquire(args.output)

if __name__=='__main__':main()
