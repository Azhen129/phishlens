"""Retrieve only the reviewed, hash-pinned Phase5 corpus snapshots as inert data."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.acquire_english_dataset import download,HOSTS

def main():
    HOSTS.update({'shomir.net','ndownloader.figshare.com','s3-eu-west-1.amazonaws.com','s3.amazonaws.com'})
    specs=json.loads((ROOT/'docs/ml/phase5/raw-snapshots.json').read_text())['files']
    output=ROOT/'work/phase5/raw';output.mkdir(parents=True,exist_ok=True)
    for spec in specs:
        path=download(spec,output)
        print(path.name, path.stat().st_size,flush=True)

if __name__=='__main__':main()
