"""Evaluation metrics (scikit-learn). Computed from real runs only —
never hand-written. Unsupported-conclusion rate = conclusions with
no supporting graph edge / total conclusions.
"""
from __future__ import annotations
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

def compute_metrics(y_true: list[str], y_pred: list[str], tool_calls: list[int],
                    times: list[float], unsupported: int, total_conclusions: int) -> dict:
    # Map labels to binary: malicious=1, benign/abstain=0 (abstention is NOT a malicious claim).
    yt = [1 if t == "malicious" else 0 for t in y_true]
    yp = [1 if p == "MALICIOUS" else 0 for p in y_pred]
    tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel().tolist()
    precision = float(precision_score(yt, yp, zero_division=0))
    recall = float(recall_score(yt, yp, zero_division=0))
    f1 = float(f1_score(yt, yp, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) else 0.0
    definitive = sum(1 for p in y_pred if p in ("MALICIOUS", "BENIGN"))
    return {
        "n_traces": len(y_true),
        "true_positives": int(tp), "false_positives": int(fp),
        "false_negatives": int(fn), "true_negatives": int(tn),
        "precision": round(precision, 4), "recall": round(recall, 4), "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "investigation_completion_rate": round(definitive / len(y_true), 4) if y_true else 0.0,
        "abstentions": int(len(y_true) - definitive),
        "avg_tool_calls": round(sum(tool_calls) / len(tool_calls), 2) if tool_calls else 0.0,
        "avg_execution_time_seconds": round(sum(times) / len(times), 3) if times else 0.0,
        "unsupported_conclusion_rate": round(unsupported / total_conclusions, 4) if total_conclusions else 0.0,
        "unsupported_conclusions": int(unsupported), "total_conclusions": int(total_conclusions),
    }
