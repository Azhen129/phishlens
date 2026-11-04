"""Frozen Phase 4 preparation: real phishing, ham-only licensed CSVs, holdouts.

No model fitting or evaluation occurs here. All content is inert. Global
duplicate/campaign constraints are computed before selecting main/external
partitions; external components are removed from main before hash sampling.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from langid.langid import LanguageIdentifier, model
from threadpoolctl import threadpool_limits

from backend.ml_features import canonical_text
from backend.ml_training import Row, UnionFind, build_groups
from scripts import acquire_english_dataset as acquisition

PROTOCOL = "english-preparation-v1-2026-11-02"
FIGSHARE_API = "https://api.figshare.com/v2/articles/25432108"
FIGSHARE_PAGE = "https://figshare.com/articles/dataset/Seven_Phishing_Email_Datasets/25432108"
HAM = [
    {"filename": "figshare-Ling.csv", "url": "https://ndownloader.figshare.com/files/45117802", "sha256": "9407c9e022accc6c831e54c5226b99b30ac4ae07682e63f5d483ed0ec17ff23c", "md5": "eac6399dc0c7ae455aebb64423dadc8b", "limit": 10_000_000, "original": {"0": 2401, "1": 458}},
    {"filename": "figshare-Enron.csv", "url": "https://ndownloader.figshare.com/files/45117805", "sha256": "11f28a5bdd3603f1829681ab6b55071b5f9af781b4e6694e39216b2996a96883", "md5": "10489e0fdcc8af6fe62135c689367d40", "limit": 46_000_000, "original": {"0": 15791, "1": 13976}},
    {"filename": "figshare-Assassin.csv", "url": "https://ndownloader.figshare.com/files/45117799", "sha256": "3bfe8f8abff89f69a98456be50413c2fcb20a476141116dd84ee1507b980c00e", "md5": "d921e0b2333bfaa058bd38193e6b3fbd", "limit": 16_000_000, "original": {"0": 4091, "1": 1718}},
]
acquisition.HOSTS.update({"ndownloader.figshare.com", "s3-eu-west-1.amazonaws.com", "s3.amazonaws.com", "api.figshare.com"})


class InertText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.hidden = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript"}:
            self.hidden += 1
        elif tag in {"p", "div", "br", "li", "tr"}:
            self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, value):
        if not self.hidden:
            self.parts.append(value)


def full_inert_text(value: str) -> str:
    """Language screen the entire bounded source text, not its first sentence."""
    if len(value) > 5_000_000:
        raise ValueError("A source email exceeds the reviewed five-million-character limit.")
    if re.search(r"</?(?:html|body|div|p|a|script|style|table)\b", value, re.I):
        parser = InertText()
        parser.feed(value)
        value = " ".join(parser.parts)
    return " ".join(unicodedata.normalize("NFKC", unescape(value)).split()).casefold()


def clean_field(value: str | None) -> str:
    value = value or ""
    return "" if value.strip().casefold() in {"nan", "none", "null"} else value


def rows_from_ham(paths: list[Path], counts: Counter):
    for spec, path in zip(HAM, paths, strict=True):
        original = Counter()
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not {"subject", "body", "label"} <= set(reader.fieldnames or []):
                raise ValueError("Ham source schema differs from reviewed fields.")
            for number, item in enumerate(reader):
                label = str(item["label"])
                if label not in {"0", "1"}:
                    raise ValueError("Unknown original label in ham source.")
                original[label] += 1
                counts["original:" + path.stem + ":" + label] += 1
                if label != "0":
                    continue
                text = "Subject: " + clean_field(item["subject"]) + "\n\n" + clean_field(item["body"])
                yield {"text": text, "label": 0, "source": "Figshare-" + path.stem.removeprefix("figshare-"), "group": "", "row_id": path.stem + ":" + str(number), "date": item.get("date", ""), "language": "und", "external": False}
        if dict(original) != spec["original"]:
            raise ValueError("Original class counts differ from reviewed Figshare snapshot.")


def subject_key(value: str) -> str:
    subject = value.partition("\n\n")[0].removeprefix("Subject:").strip()
    subject = unicodedata.normalize("NFKC", unescape(subject)).casefold()
    subject = re.sub(r"^(?:(?:re|fw|fwd)\s*:\s*)+", "", subject)
    subject = re.sub(r"https?://\S+|\b[^\s@]+@[^\s@]+\b", " ADDRTOKEN ", subject)
    subject = re.sub(r"\d+", " NUMTOKEN ", subject)
    subject = " ".join(re.findall(r"\w+", subject))
    # Empty or one-character subjects are not useful campaign constraints.
    return subject if len(re.sub(r"\W|_", "", subject)) >= 8 else ""


def has_subject_annotation(value: str) -> bool:
    """Quarantine acquisition/MUA label tags without deleting body evidence."""
    subject = value.partition("\n\n")[0].removeprefix("Subject:")
    return bool(re.search(r"\[\s*(?:spam|phish|phishing)\s*\]", subject, re.I))


def body_only(value: str) -> str:
    body = value.partition("\n\n")[2]
    body = re.sub(r"(?m)^\s*>+\s?", "", body)
    body = re.sub(r"\b[a-fA-F0-9]{16,}\b", " TRACKINGTOKEN ", body)
    return body or value


def deduplicate(rows: list[dict]) -> tuple[list[dict], dict]:
    buckets = defaultdict(list)
    for row in rows:
        key = hashlib.sha256(canonical_text(row["text"], "email").encode()).hexdigest()
        buckets[key].append(row)
    kept, stats = [], Counter()
    for key in sorted(buckets):
        entries = buckets[key]
        if len({r["label"] for r in entries}) > 1:
            stats["conflicting_canonical_groups_quarantined"] += 1
            stats["conflicting_rows_quarantined"] += len(entries)
            continue
        # Prefer external representative when an exact duplicate spans main
        # and external. Main copies can never leak back into model fitting.
        representative = min(entries, key=lambda r: (not r["external"], r["source"], r["row_id"]))
        row = dict(representative)
        row["identifier"] = key
        row["external"] = any(r["external"] for r in entries)
        row["origins"] = sorted({r["source"] for r in entries})
        stats["exact_duplicate_rows_removed"] += len(entries) - 1
        if row["external"]:
            stats["main_copies_touching_exact_external"] += sum(not r["external"] for r in entries)
        kept.append(row)
    stats["canonical_unique_retained"] = len(kept)
    return kept, dict(stats)


def global_groups(rows: list[dict], max_comparisons: int) -> tuple[list[str], dict]:
    uf = UnionFind(len(rows))
    passes = {}
    for name, threshold, text_fn in [("full_text", .90, lambda value: value), ("body_template", .80, body_only)]:
        representations = [Row(text_fn(r["text"]), r["label"], r["source"], r["identifier"], "") for r in rows]
        grouped, audit = build_groups(representations, "email", threshold=threshold, max_comparisons=max_comparisons)
        members = {}
        for i, group in enumerate(grouped):
            if group in members:
                uf.union(i, members[group])
            else:
                members[group] = i
        passes[name] = audit
        del representations, grouped
    subjects, subject_unions = {}, 0
    for i, row in enumerate(rows):
        subject = subject_key(row["text"])
        if not subject:
            continue
        if subject in subjects:
            uf.union(i, subjects[subject])
            subject_unions += 1
        else:
            subjects[subject] = i
    components = defaultdict(list)
    for i in range(len(rows)):
        components[uf.find(i)].append(i)
    ids = [""] * len(rows)
    for indexes in components.values():
        key = "global:" + min(rows[i]["identifier"] for i in indexes)
        for i in indexes:
            ids[i] = key
    return ids, {"passes": passes, "global_subject_unions": subject_unions, "components": len(components), "largest_component": max(map(len, components.values()), default=0), "threshold_policy": "full subject/body Jaccard>=0.90; body-only quote/tracking normalized Jaccard>=0.80; global normalized subjects (>=8 characters). No labels used for unions. Exact deterministic prefix-filter search, fail closed at bound."}


def write_csv(path: Path, rows: list[dict]) -> dict:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=acquisition.FIELDS, lineterminator="\n")
        writer.writeheader()
        for row in sorted(rows, key=lambda r: r["identifier"]):
            writer.writerow({name: row[name] for name in acquisition.FIELDS})
    return {"path": path.as_posix(), "sha256": acquisition.digest(path), "rows": len(rows), "class_balance": dict(Counter(str(r["label"]) for r in rows)), "sources": dict(Counter(r["source"] for r in rows)), "groups": len({r["group"] for r in rows}), "label_mapping": {"0": "legitimate", "1": "phishing"}}


def separate_external(rows: list[dict], groups: list[str], max_main_rows: int):
    """Purge every main row in an external-connected global component."""
    for row, group in zip(rows, groups, strict=True):
        row["group"] = group
    external_groups = {r["group"] for r in rows if r["external"]}
    external = [r for r in rows if r["external"]]
    candidates = [r for r in rows if not r["external"] and r["group"] not in external_groups]
    excluded = [r for r in rows if not r["external"] and r["group"] in external_groups]
    main = sorted(candidates, key=lambda r: r["identifier"])[:max_main_rows]
    if {r["group"] for r in main} & external_groups:
        raise AssertionError("External group appeared in main data.")
    return main, external, excluded, candidates


def prepare(output: Path, max_main_rows: int, max_comparisons: int) -> dict:
    csv.field_size_limit(10_000_000)
    output.mkdir(parents=True, exist_ok=True)
    base_path = output / "english-nazario-masc.csv"
    base_provenance_path = output / "english-nazario-masc-provenance.json"
    if not base_path.exists() or not base_provenance_path.exists():
        acquisition.prepare(output)
    base_provenance = json.loads(base_provenance_path.read_text(encoding="utf-8"))
    if acquisition.digest(base_path) != base_provenance["prepared"]["sha256"]:
        raise ValueError("Base acquisition CSV no longer matches its provenance checksum.")
    paths = [acquisition.download(spec, output) for spec in HAM]
    counts = Counter()
    with base_path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        row["label"] = int(row["label"])
        row["external"] = row["source"].startswith("MASC-") or row["source"] in {"nazario-phishing-2024", "nazario-phishing-2025"}
    rows.extend(rows_from_ham(paths, counts))
    annotation_rejections = Counter()
    unannotated = []
    for row in rows:
        if has_subject_annotation(row["text"]):
            annotation_rejections[row["source"] + ":" + str(row["label"])] += 1
        else:
            unannotated.append(row)
    source_records_considered = len(rows)
    rows = unannotated
    identifier = LanguageIdentifier.from_modelstring(model, norm_probs=True)
    accepted, rejected, language_cache = [], Counter(), {}
    for number, row in enumerate(rows, 1):
        language_text = full_inert_text(row["text"])
        key = hashlib.sha256(language_text.encode()).hexdigest()
        if key not in language_cache:
            language_cache[key] = identifier.classify(language_text)
        language, probability = language_cache[key]
        if language != "en" or probability < .90:
            rejected[row["source"] + ":" + language] += 1
        else:
            row["language"] = "en"
            accepted.append(row)
        if number % 2000 == 0:
            print(f"Language screened {number}/{len(rows)} records.", flush=True)
    del language_cache
    retained, dedup_audit = deduplicate(accepted)
    print(f"Globally grouping {len(retained)} canonical unique English records before any split.", flush=True)
    groups, grouping_audit = global_groups(retained, max_comparisons)
    main, external, excluded, main_candidates = separate_external(retained, groups, max_main_rows)
    if len({r["label"] for r in main}) != 2 or len({r["label"] for r in external}) != 2:
        raise ValueError("Prepared main and external sets must each contain real examples of both labels.")
    main_info = write_csv(output / "english-train.csv", main)
    external_info = write_csv(output / "english-external.csv", external)
    audit = {
        "protocol": PROTOCOL, "original_figshare_counts": dict(counts), "source_records_considered": source_records_considered,
        "subject_annotation_quarantine": {"rule": "Subject only, case-insensitive bracketed [spam], [phish], or [phishing]; applies regardless of label/source/split, before language/dedup. Body evidence unchanged.", "removed_by_source_and_label": dict(annotation_rejections), "removed_rows": sum(annotation_rejections.values())},
        "language_accepted": len(accepted), "language_rejected_by_source_and_language": dict(rejected),
        "language_policy": "Full inert source text, langid normalized English score>=0.90; imperfect language filter, not phishing confidence.",
        "deduplication": dedup_audit, "global_grouping": grouping_audit,
        "reserved_external_sources": ["MASC-Enron", "MASC-W3C", "nazario-phishing-2024", "nazario-phishing-2025"],
        "main_rows_removed_for_external_component": len(excluded),
        "main_rows_removed_by_source": dict(Counter(r["source"] for r in excluded)),
        "main_before_sampling": len(main_candidates), "sampling_rows_removed": len(main_candidates) - len(main),
        "sampling_policy": f"Label-blind smallest SHA-256 canonical text hashes, cap{max_main_rows}; frozen before model evaluation.",
        "main_external_group_intersection": 0, "main": main_info, "external": external_info,
    }
    (output / "preparation-audit.json").write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    limitations = [
        "Main phishing and legitimate labels are confounded with corpus family; source artifacts remain despite removed metadata and source/era stress tests.",
        "Figshare label0 is inherited legitimate/ham labeling; not independent modern security adjudication. Generic spam label1 is excluded, never claimed as phishing.",
        "Figshare curators license their release CC BY4.0; their original constituent corpora have separate collection and original-sender rights history. Explicit curator permission does not authenticate original senders.",
        "External MASC legitimate labels are contextual routine-email genre, not security annotations. Only80 original documents before cleaning.",
        "Nazario hand labeling can contain errors and collection/anonymization/era bias; curated real inbox data is not exhaustive.",
        "Template and thread disjointness is lexical and bounded to the shared first600-token representation; semantic/paraphrased campaigns may remain related.",
        "Offline language screening can misclassify short, mixed-language or technical emails; normalized langid score is not model confidence.",
        "Artificial class balance and corpus-era biases prevent interpreting benchmark calibration as deployment prevalence calibration.",
    ]
    provenance = {
        "name": "English Nazario phishing / Figshare ham-only", "version": PROTOCOL, "task": "email", "approved_for_training": True,
        "supported_languages": ["en"], "source_url": FIGSHARE_PAGE, "doi": "10.6084/m9.figshare.25432108.v1",
        "license": "CC BY 4.0 (Nazario and Figshare); external MASC CC BY 3.0 US", "license_url": "https://creativecommons.org/licenses/by/4.0/",
        "attribution": "José Nazario, Phishing Corpus; Arifa Islam Champa and Md Fazle Rabbi, Seven Phishing Email Datasets (2024), DOI10.6084/m9.figshare.25432108.v1; American National Corpus Project, MASC (external only). Cite Champa, Rabbi and Zibran (2024), Curated Datasets and Feature Analysis for Phishing Email Detection with Machine Learning.",
        "permission_basis": "Nazario official README/LICENSE explicitly CC BY4.0. Figshare original article/API explicitly CC BY4.0. MASC official page explicitly CC BY3.0 US and any purpose. Attribution/adaptation notices in docs/ml/phase4/DATASET_RESEARCH.md.",
        "collection_notes": "Real manually classified inbox phishing versus curator-labeled legitimate Ling/Enron/Assassin emails. Use only Figshare original label0; every original label1 is excluded because merged historical spam is not reliable phishing ground truth. Reserve MASC and newest Nazario files externally; global lexical/thread groups exclude main records touching external.",
        "validation_scope": "Offline English corpus benchmark and limited external historical legitimate/newer inbox phishing stress evaluation. This does not establish broad English mail accuracy, source-independent generalization or deployment confidence.",
        "changes": "Subject plus decoded body only; no sender/transport/features/urls columns. Quarantine explicit bracketed spam/phish/phishing subject annotations regardless of label. Offline full-text English screen; canonical dedup and conflicting-label quarantine; .90 fulltext/.80 body template + global subject grouping; remove external-connected main components; label-blind SHA256 sample cap before training.",
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "raw": [*base_provenance["raw"], *[{"url": spec["url"], "path": path.as_posix(), "sha256": acquisition.digest(path), "bytes": path.stat().st_size, "publisher_md5": spec["md5"]} for spec, path in zip(HAM, paths, strict=True)]],
        "prepared": main_info, "external": external_info, "preparation_audit_sha256": acquisition.digest(output / "preparation-audit.json"),
        "protocol": PROTOCOL, "limitations": limitations,
    }
    (output / "english-train-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    external_provenance = {**provenance, "name": "English reserved MASC / newer Nazario external stress set", "prepared": external_info, "approved_for_training": False}
    (output / "english-external-provenance.json").write_text(json.dumps(external_provenance, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"main": main_info, "external": external_info, "deduplication": dedup_audit, "main_rows_removed_for_external_component": len(excluded)}, indent=2), flush=True)
    return audit


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("work/phase4/raw"))
    parser.add_argument("--max-main-rows", type=int, default=10_000)
    parser.add_argument("--max-comparisons", type=int, default=10_000_000)
    args = parser.parse_args()
    if args.max_main_rows < 100 or args.max_comparisons < 1:
        raise ValueError("Invalid preparation bounds.")
    with threadpool_limits(limits=1):
        prepare(args.output, args.max_main_rows, args.max_comparisons)


if __name__ == "__main__":
    main()
