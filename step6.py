"""
Шаг 6: методы и роуты для модели сетевого трафика.

Что есть в этом файле:
  - функция classify_one_flow()
роуты:
    POST /traffic/predict
    POST /traffic/predict_batch

Что нужно подавать:
  JSON с теми же числовыми признаками, которые были в B_labeled.csv
  (кроме label и label_name).
"""

from pathlib import Path

import pandas as pd
from catboost import CatBoostClassifier
from fastapi import APIRouter

ROOT = Path(__file__).resolve().parent

FILE_MODEL_FULL = ROOT / "traffic_model_full.cbm"
FILE_MODEL_SMALL = ROOT / "traffic_model.cbm"

TYPE_NAMES = {
    0: "normal",
    1: "DDoS",
    2: "PortScan",
    3: "Bot",
    4: "Infiltration",
    5: "Web Attack",
    6: "Brute Force",
    7: "DoS",
}

FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

model_path = FILE_MODEL_FULL if FILE_MODEL_FULL.is_file() else FILE_MODEL_SMALL
model = CatBoostClassifier()
model.load_model(str(model_path))
print("Traffic-модель загружена из", model_path.name)

router = APIRouter(prefix="/traffic", tags=["Traffic model"])


def prepare_one_flow(flow_dict):
    """
    Собираем одну строку признаков в правильном порядке.
    Если какого-то поля нет, то ставим 0.
    """
    row = {}
    for col in FEATURE_COLUMNS:
        value = flow_dict.get(col, 0)
        row[col] = value
    return row


def classify_one_flow(flow_dict):
    """
    Принимаем один flow, возвращает класс и вероятность.
    """
    row = prepare_one_flow(flow_dict)
    X = pd.DataFrame([row])

    pred_class = int(model.predict(X).flatten()[0])
    probas = model.predict_proba(X)[0]
    class_index = list(model.classes_).index(pred_class)
    confidence = round(float(probas[class_index]), 4)

    return {
        "flow": row,
        "type_code": pred_class,
        "type_name": TYPE_NAMES.get(pred_class, "unknown"),
        "probability": confidence,
    }


@router.post("/predict")
def predict_one(flow: dict):
    return classify_one_flow(flow)


@router.post("/predict_batch")
def predict_batch(flows: list[dict]):
    rows = [prepare_one_flow(flow) for flow in flows]
    X = pd.DataFrame(rows)

    pred_classes = model.predict(X).flatten()
    all_probas = model.predict_proba(X)
    classes_list = list(model.classes_)

    results = []
    for i, row in enumerate(rows):
        pc = int(pred_classes[i])
        ci = classes_list.index(pc)
        conf = round(float(all_probas[i][ci]), 4)
        results.append({
            "flow": row,
            "type_code": pc,
            "type_name": TYPE_NAMES.get(pc, "unknown"),
            "probability": conf,
        })

    return results
