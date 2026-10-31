"""Reproducible baseline anomaly detection with chronological holdout evaluation.

Models are advisory. An anomaly is not proof of malicious activity. Only locally
generated, hash-checked model files are loaded; model uploads are unsupported.
"""
from collections import defaultdict
from datetime import datetime, timezone
import io
import math

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sqlalchemy import select, update, func, and_

from . import db as D
from .crypto import atomic_write, canon, dumps, loads, now, sha, uid
from .schema import parse_time
from .service import DomainError, row, rows

WINDOW_SECONDS = 300
FEATURES = ["events", "process_events", "file_events", "network_events", "auth_failures", "high_severity_events", "unique_processes", "unique_destinations", "unique_paths", "unknown_event_times"]


def time_number(value):
    parsed = parse_time(value)
    if parsed is None:
        raise DomainError("TIME_RANGE", "Use a timestamp with an explicit timezone", 422)
    return datetime.fromisoformat(parsed.replace("Z", "+00:00")).timestamp()


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def select_windows(service, start, end, asset_id=None, snapshot=None):
    a, b = time_number(start), time_number(end)
    if b <= a or b - a > 90 * 86400:
        raise DomainError("TIME_RANGE", "Choose an increasing range no longer than 90 days", 422)
    with service.db.read() as c:
        if snapshot is None:
            snapshot = c.execute(select(func.max(D.evidence.c.sequence))).scalar() or 0
        # Received time is immutable and always present. Event time may be absent or untrusted.
        query = select(D.evidence).where(and_(D.evidence.c.received_at >= iso(a), D.evidence.c.received_at < iso(b), D.evidence.c.sequence <= snapshot))
        if asset_id:
            query = query.where(D.evidence.c.asset_id == asset_id)
        items = rows(c, query.order_by(D.evidence.c.sequence).limit(100001))
    if len(items) > 100000:
        raise DomainError("MODEL_RANGE_TOO_LARGE", "Narrow the range to at most 100,000 evidence records", 422)
    grouped = {}
    for item in items:
        env = loads(item["envelope"])
        stamp = time_number(item["received_at"])
        bucket = int(stamp // WINDOW_SECONDS) * WINDOW_SECONDS
        key = (item["asset_id"], bucket)
        if key not in grouped:
            grouped[key] = {"asset_id": key[0], "start": iso(bucket), "end": iso(bucket + WINDOW_SECONDS), "ids": [], "counts": [0] * 10, "processes": set(), "destinations": set(), "paths": set()}
        w = grouped[key]
        w["ids"].append(item["id"])
        counts = w["counts"]
        counts[0] += 1
        et = item["event_type"]
        counts[1] += int(et.startswith("process."))
        counts[2] += int(et.startswith(("file.", "fim.")))
        counts[3] += int(et.startswith("network."))
        counts[4] += int(et == "auth.failure")
        counts[5] += int(item["severity"] >= 3)
        counts[9] += int(item["occurred_at"] is None)
        subject = env.get("subject", {})
        for field, pool in (("process", "processes"), ("dst_ip", "destinations"), ("path", "paths")):
            if subject.get(field):
                w[pool].add(str(subject[field]))
    result = []
    for w in sorted(grouped.values(), key=lambda w: (w["start"], w["asset_id"])):
        w["counts"][6:9] = [len(w["processes"]), len(w["destinations"]), len(w["paths"])]
        for field in ("processes", "destinations", "paths"):
            del w[field]
        result.append(w)
    return result, snapshot


def train(service, payload):
    if payload.get("confirm_benign") is not True:
        raise DomainError("BENIGN_REVIEW_REQUIRED", "A reviewer must confirm the baseline range is benign", 422)
    if not payload.get("start") or not payload.get("end"):
        raise DomainError("TIME_RANGE", "Baseline training requires explicit start and end timestamps", 422)
    windows, snapshot = select_windows(service, payload["start"], payload["end"], payload.get("asset_id"), payload.get("snapshot_sequence"))
    if len(windows) < 30:
        raise DomainError("INSUFFICIENT_BASELINE", "At least 30 occupied five-minute asset windows are required; collect a longer reviewed benign baseline", 422)
    cutoff = max(20, int(len(windows) * .7))
    # Never split records from the same clock interval across train and holdout.
    while cutoff < len(windows) and windows[cutoff]["start"] == windows[cutoff-1]["start"]:
        cutoff += 1
    if len(windows) - cutoff < 5:
        raise DomainError("INSUFFICIENT_HOLDOUT", "Need at least five later windows for a separate holdout evaluation", 422)
    training, holdout = windows[:cutoff], windows[cutoff:]
    training_ids = [eid for w in training for eid in w["ids"]]
    holdout_ids = [eid for w in holdout for eid in w["ids"]]
    identity = {"algorithm": "IsolationForest", "version": "1.0.0", "features": FEATURES, "training_ids": training_ids, "holdout_ids": holdout_ids, "seed": 42}
    input_digest = sha(canon(identity))
    model_id = input_digest[:32]
    with service.db.read() as c:
        existing = row(c, select(D.models).where(D.models.c.id == model_id))
    if existing:
        return {"model_id": model_id, "duplicate": True, "manifest": loads(existing["manifest"])}
    x = np.log1p(np.array([w["counts"] for w in training], dtype=float))
    x_holdout = np.log1p(np.array([w["counts"] for w in holdout], dtype=float))
    model = IsolationForest(n_estimators=100, max_samples=min(256, len(x)), contamination=.05, random_state=42, n_jobs=1)
    model.fit(x)
    predictions = model.predict(x_holdout)
    false_positives = int(np.sum(predictions == -1))
    buffer = io.BytesIO()
    joblib.dump(model, buffer, compress=3)
    encoded = buffer.getvalue()
    digest = sha(encoded)
    path = service.root / "models" / (model_id + ".joblib")
    atomic_write(path, encoded)
    manifest = {"model_id": model_id, "algorithm": "IsolationForest", "implementation": "scikit-learn", "library_version": sklearn.__version__, "feature_version": "1.0.0", "features": FEATURES, "transform": "log1p", "window_seconds": WINDOW_SECONDS, "clock_basis": "received_at", "input_sha256": input_digest, "model_sha256": digest, "snapshot_sequence": str(snapshot), "baseline_start": parse_time(payload["start"]), "baseline_end": parse_time(payload["end"]), "training_windows": len(training), "holdout_windows": len(holdout), "training_evidence_ids": training_ids, "holdout_evidence_ids": holdout_ids, "train_last_window": training[-1]["start"], "holdout_first_window": holdout[0]["start"], "median_features": np.median(np.array([w["counts"] for w in training]), axis=0).tolist(), "training_review": {"confirmed_benign": True, "actor_id": payload.get("actor_id", "job-initiator"), "note": str(payload.get("review_note", "Reviewer confirmed selected interval benign"))[:2000]}, "parameters": {"n_estimators": 100, "contamination": .05, "random_state": 42, "max_samples": min(256, len(x))}, "evaluation": {"benign_holdout_false_positives": false_positives, "benign_holdout_windows": len(holdout), "false_positive_rate": false_positives / len(holdout), "attack_recall": None, "precision": None, "limitation": "Only a reviewed benign holdout was evaluated. Attack recall and precision require separately labeled attack data."}, "created_at": now(), "path": "models/" + path.name}
    atomic_write(path.with_suffix(".json"), canon(manifest))
    with service.db.tx() as c:
        c.execute(update(D.models).values(active=False))
        c.execute(D.models.insert().values(id=model_id, name="Isolation Forest " + manifest["created_at"], sha256=digest, manifest=dumps(manifest), created_at=now(), active=True))
        service.audit(c, payload.get("actor_id", "system"), "MODEL_TRAINED", model_id, details={"model_sha256": digest, "input_sha256": input_digest, "training_windows": len(training), "holdout_windows": len(holdout), "false_positive_rate": manifest["evaluation"]["false_positive_rate"]})
    return {"model_id": model_id, "duplicate": False, "manifest": manifest}


def score(service, payload):
    with service.db.read() as c:
        query = select(D.models).where(D.models.c.id == payload["model_id"]) if payload.get("model_id") else select(D.models).where(D.models.c.active == True)
        entry = row(c, query)
    if not entry:
        raise DomainError("MODEL_UNAVAILABLE", "Train a reviewed baseline model first", 422)
    manifest = loads(entry["manifest"])
    path = service.root / "models" / (entry["id"] + ".joblib")
    encoded = path.read_bytes()
    if sha(encoded) != entry["sha256"] or sha(encoded) != manifest["model_sha256"]:
        raise DomainError("MODEL_HASH", "Model bytes do not match the registered version", 409)
    if manifest["library_version"] != sklearn.__version__:
        raise DomainError("MODEL_VERSION", "Retrain the model after changing the scikit-learn version", 409)
    start = payload.get("start") or manifest["baseline_end"]
    end = payload.get("end") or now()
    if time_number(start) < time_number(manifest["baseline_end"]):
        raise DomainError("TRAINING_OVERLAP", "Scoring must begin at or after the reviewed baseline end to avoid evaluation leakage", 422)
    windows, snapshot = select_windows(service, start, end, payload.get("asset_id"), payload.get("snapshot_sequence"))
    if not windows:
        return {"model_id": entry["id"], "windows_scored": 0, "new_alerts": 0, "snapshot_sequence": str(snapshot)}
    # The only deserialized files are generated locally and checked against DB + manifest hashes.
    model = joblib.load(io.BytesIO(encoded))
    if not isinstance(model, IsolationForest):
        raise DomainError("MODEL_TYPE", "Registered model is not the supported algorithm", 409)
    decisions = model.decision_function(np.log1p(np.array([w["counts"] for w in windows], dtype=float)))
    median = manifest["median_features"]
    added = 0
    results = []
    with service.db.tx() as c:
        for w, decision in zip(windows, decisions):
            decision = float(decision)
            anomaly = min(1., max(0., .5 - decision))
            results.append({"asset_id": w["asset_id"], "start": w["start"], "decision_function": decision, "anomalous": decision < 0})
            if decision >= 0:
                continue
            dedup = "model:" + entry["id"] + ":" + w["asset_id"] + ":" + w["start"]
            if row(c, select(D.alerts.c.id).where(D.alerts.c.dedup_key == dedup)):
                continue
            deviations = sorted([{"feature": name, "observed": value, "baseline_median": baseline, "absolute_difference": abs(value - baseline)} for name, value, baseline in zip(FEATURES, w["counts"], median)], key=lambda x: x["absolute_difference"], reverse=True)[:3]
            last = row(c, select(D.evidence).where(D.evidence.c.id == w["ids"][-1]))
            asset = row(c, select(D.assets).where(D.assets.c.id == w["asset_id"]))
            s, k = last["severity"] / 5, (asset["criticality"] if asset else 3) / 5
            correlation = 0.0
            risk = round(100 * (.4 * s + .3 * anomaly + .2 * correlation + .1 * k), 2)
            components = {"severity": s, "anomaly": anomaly, "correlation": correlation, "asset_criticality": k, "weights": {"severity": .4, "anomaly": .3, "correlation": .2, "asset_criticality": .1}, "decision_function": decision, "window_start": w["start"], "window_end": w["end"], "features": dict(zip(FEATURES, w["counts"])), "deviations": deviations, "evidence_ids": w["ids"], "baseline_start": manifest["baseline_start"], "baseline_end": manifest["baseline_end"], "quality_note": "Receive-time windows; delayed collection can distort rates. Correlation contribution is zero until an analyst correlates evidence."}
            explanation = "Unusual five-minute activity versus reviewed baseline. Largest feature differences: " + "; ".join(f"{x['feature']}={x['observed']} (median {x['baseline_median']:g})" for x in deviations) + ". Analyst review is required."
            c.execute(D.alerts.insert().values(id=uid(), evidence_id=last["id"], asset_id=w["asset_id"], rule_id="isolation-forest-v1", severity=last["severity"], risk=risk, explanation=explanation, status="NEW", model_id=entry["id"], components=dumps(components), created_at=now(), dedup_key=dedup))
            added += 1
        service.audit(c, payload.get("actor_id", "system"), "MODEL_SCORED", entry["id"], details={"windows": len(windows), "new_alerts": added, "snapshot_sequence": str(snapshot)})
    return {"model_id": entry["id"], "windows_scored": len(windows), "anomalous_windows": sum(int(d < 0) for d in decisions), "new_alerts": added, "snapshot_sequence": str(snapshot), "window_results": results[:1000], "results_truncated": len(results) > 1000, "limitation": "Anomaly scores are advisory and do not establish malicious intent."}
