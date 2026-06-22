#!/usr/bin/env python3
"""
Phase 3.1 — train the XGBoost intrusion model and export it to ONNX.

Run from the repo root:   python scripts/export_onnx.py

Produces:
  models/xgboost_intrusion.onnx   the portable model (loaded by the C++ server)
  models/feature_order.json       the 58-feature order (the train/serve contract)
  models/threshold.txt            the F1-optimal decision threshold

NOTE (see DECISIONS.md D17): we train on the UNSW CSV (Argus/Bro features) — the
only labeled data we have. Our C++ extractor's features diverge in distribution,
so AFTER building the inference server we empirically test this skew by scoring
our own pipeline's flows and checking the known attacker subnet (175.45.176.0/24)
gets flagged. This script is the baseline model for that test.

The feature ORDER here MUST match cpp/src/feature_schema.h exactly, or the C++
server feeds the model mislabeled inputs and every prediction is wrong.
"""
import os
import sys
import json
import numpy as np
import pandas as pd

# Make `from preprocessing.preprocessing import ...` work when run from root.
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))
from preprocessing.preprocessing import preprocess_train, preprocess_test  # noqa: E402

from xgboost import XGBClassifier
from sklearn.metrics import f1_score, roc_auc_score, classification_report

# --- ONNX conversion (onnxmltools converts XGBoost directly) ---
from onnxmltools.convert import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType
import onnxruntime as ort

# ===================================================================
# THE FEATURE-ORDER CONTRACT — must equal cpp/src/feature_schema.h.
# 21 one-hot columns + 37 raw numerics = 58 features.
# ===================================================================
OHE = (
    ["proto_arp", "proto_ospf", "proto_other", "proto_sctp",
     "proto_tcp", "proto_udp", "proto_unas"]
    + ["service_-", "service_dns", "service_ftp", "service_ftp-data",
       "service_http", "service_other", "service_pop3", "service_smtp",
       "service_ssh"]
    + ["state_CON", "state_FIN", "state_INT", "state_REQ", "state_other"]
)
NUM = [
    "ackdat", "ct_dst_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "ct_flw_http_mthd", "ct_ftp_cmd", "ct_src_dport_ltm", "ct_src_ltm",
    "ct_srv_dst", "ct_srv_src", "ct_state_ttl", "dbytes", "dinpkt", "djit",
    "dload", "dloss", "dmean", "dpkts", "dttl", "dur", "dwin", "is_ftp_login",
    "is_sm_ips_ports", "rate", "response_body_len", "sbytes", "sinpkt", "sjit",
    "sload", "sloss", "smean", "spkts", "sttl", "swin", "synack", "tcprtt",
    "trans_depth",
]
COLUMNS = OHE + NUM
assert len(COLUMNS) == 58, len(COLUMNS)

# Best hyperparameters from the comparison study (Table 3.1) — no re-tuning.
BEST_PARAMS = dict(
    n_estimators=1000, max_depth=4, learning_rate=0.01,
    subsample=0.7, colsample_bytree=0.8, min_child_weight=1,
    gamma=0.1, reg_alpha=1.0, reg_lambda=2.0,
    eval_metric="logloss", random_state=42, n_jobs=-1,
)


def load(path):
    # utf-8-sig strips the BOM the Kaggle CSVs start with.
    return pd.read_csv(path, encoding="utf-8-sig")


def to_X(df_tree):
    # Reindex to the EXACT contract order; any missing one-hot column -> 0.
    # Return a numpy array (NOT a DataFrame) so the booster uses default
    # f0..f57 feature names — required by the onnxmltools converter. Column
    # ORDER is already pinned by the reindex above, so dropping names is safe.
    return df_tree.reindex(columns=COLUMNS, fill_value=0).values.astype(np.float32)


def main():
    train = load("data/UNSW_NB15_training-set copy.csv")
    test = load("data/UNSW_NB15_testing-set copy.csv")

    # Reuse the exact preprocessing pipeline (bucketing + one-hot; raw numerics
    # for the tree model). df_model_tree = one-hot + numerics + label.
    _, _, train_tree, artifacts = preprocess_train(train)
    _, _, test_tree = preprocess_test(test, artifacts)

    X_train, y_train = to_X(train_tree), train_tree["label"].values
    X_test,  y_test  = to_X(test_tree),  test_tree["label"].values
    print(f"train {X_train.shape}  test {X_test.shape}  (expect 58 cols)")

    # scale_pos_weight balances the classes (same as the study's base model).
    spw = (y_train == 0).sum() / (y_train == 1).sum()
    model = XGBClassifier(scale_pos_weight=spw, **BEST_PARAMS)
    print("training XGBoost...")
    model.fit(X_train, y_train)

    # Sanity: native XGBoost metrics on the test set.
    prob = model.predict_proba(X_test)[:, 1]
    print(f"native test ROC-AUC: {roc_auc_score(y_test, prob):.4f}")

    # F1-optimal threshold (sweep 0.01..0.99), as in the study.
    grid = np.linspace(0.01, 0.99, 99)
    f1s = [f1_score(y_test, (prob >= t).astype(int)) for t in grid]
    best_t = float(grid[int(np.argmax(f1s))])
    print(f"best threshold: {best_t:.2f}  (F1={max(f1s):.4f})")

    # --- Convert to ONNX. We convert the underlying BOOSTER (not the sklearn
    #     wrapper) so the model outputs a single probability tensor with no
    #     ZipMap — one float per row = attack probability, trivial to read in
    #     C++ via ONNX Runtime. ---
    onx = convert_xgboost(
        model.get_booster(),
        initial_types=[("input", FloatTensorType([None, 58]))],
        target_opset=12,
    )

    os.makedirs("models", exist_ok=True)
    onnx_path = "models/xgboost_intrusion.onnx"
    with open(onnx_path, "wb") as f:
        f.write(onx.SerializeToString())

    # --- Validate parity: ONNX vs native XGBoost on the full test set. ---
    sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    name = sess.get_inputs()[0].name
    out = sess.run(None, {name: X_test})
    # Outputs: [label (int64 [N]), probabilities (float [N,2])].
    # Column 1 of probabilities = attack probability (what the C++ server reads).
    onnx_prob = np.asarray(out[1])[:, 1]

    max_prob_diff = float(np.abs(onnx_prob - prob).max())
    label_match = float(((onnx_prob >= 0.5).astype(int) == model.predict(X_test)).mean())
    print(f"PARITY  label match: {label_match*100:.4f}%   "
          f"max prob diff: {max_prob_diff:.2e}")
    print(classification_report(
        y_test, (onnx_prob >= best_t).astype(int),
        target_names=["Normal", "Attack"]))

    # Persist the contract + threshold next to the model.
    json.dump(COLUMNS, open("models/feature_order.json", "w"), indent=2)
    open("models/threshold.txt", "w").write(f"{best_t:.4f}\n")
    print(f"\nwrote {onnx_path}, models/feature_order.json, models/threshold.txt")


if __name__ == "__main__":
    main()