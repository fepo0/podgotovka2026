"""
Шаг 3: методы и роуты для URL-модели.

Что есть в этом файле:
  - функции подготовки URL-признаков
  - функция classify_one_url()
роуты:
    POST /url/predict
    POST /url/predict_batch
"""

import re
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
from catboost import CatBoostClassifier
from fastapi import APIRouter
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent

FILE_MODEL = ROOT / "url_model.cbm"

TYPE_NAMES = {
    0: "phishing",
    1: "benign",
    2: "broken_url",
    3: "malware",
}

MAX_LEN_URL = 4096


def is_broken_url(url):
    """Битая ли строка. Если да то сразу type=2, модель не спрашиваем"""
    if url is None:
        return True
    s = str(url).strip()
    if s == "" or len(s) > MAX_LEN_URL or "\x00" in s:
        return True
    if not s.startswith("http://") and not s.startswith("https://"):
        s = "http://" + s
    try:
        host = urlparse(s).hostname
    except ValueError:
        return True
    if not host:
        return True
    return False

def make_features(url):
    """Из строки URL делаем словарь с числовыми признаками"""
    s = str(url).strip()
    full = s if s.startswith("http://") or s.startswith("https://") else "http://" + s

    try:
        parsed = urlparse(full)
    except ValueError:
        parsed = urlparse("http://broken.invalid")

    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    parts = host.split(".")
    subdomain_count = max(len(parts) - 2, 0)

    digit_count = sum(c.isdigit() for c in s)
    digit_ratio = digit_count / max(len(s), 1)
    letter_count = sum(c.isalpha() for c in s)
    letter_ratio = letter_count / max(len(s), 1)

    return {
        "url_length":        len(s),
        "host_length":       len(host),
        "path_length":       len(path),
        "query_length":      len(query),
        "dot_count":         s.count("."),
        "dash_count":        s.count("-"),
        "at_count":          s.count("@"),
        "subdomain_count":   subdomain_count,
        "digit_count":       digit_count,
        "digit_ratio":       round(digit_ratio, 4),
        "letter_ratio":      round(letter_ratio, 4),
        "is_https":          int(s.startswith("https://")),
        "has_at":            int("@" in s),
        "has_double_slash":  int("//" in s.split("://", 1)[-1]),
        "has_ip":            int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))),
        "special_chars":     len(re.findall(r"[^a-zA-Z0-9./:?&=_\-]", s)),
        "fragment_length":   len(parsed.fragment or ""),
    }

model = CatBoostClassifier()
model.load_model(str(FILE_MODEL))
print("URL-модель загружена!")

router = APIRouter(prefix="/url", tags=["URL model"])

class URLRequest(BaseModel):
    url: str

class URLBatchRequest(BaseModel):
    urls: list[str]

class PredictionResult(BaseModel):
    url: str
    type_code: int          # 0, 1, 2 или 3
    type_name: str          # "phishing", "benign", "broken_url", "malware"
    probability: float      # уверенность модели (для type=2 всегда 1.0)


def classify_one_url(url):
    # сначала проверяем — может строка вообще не парсится как URL
    if is_broken_url(url):
        return PredictionResult(
            url=url, type_code=2, type_name="broken_url", probability=1.0
        )

    # строка нормальная, спрашиваем модель
    features = make_features(url)
    X = pd.DataFrame([features])

    pred_class = int(model.predict(X).flatten()[0])

    probas = model.predict_proba(X)[0]
    class_index = list(model.classes_).index(pred_class)
    confidence = round(float(probas[class_index]), 4)

    return PredictionResult(
        url=url,
        type_code=pred_class,
        type_name=TYPE_NAMES.get(pred_class, "unknown"),
        probability=confidence,
    )


@router.post("/predict", response_model=PredictionResult)
def predict_one(req: URLRequest):
    return classify_one_url(req.url)


@router.post("/predict_batch", response_model=list[PredictionResult])
def predict_batch(req: URLBatchRequest):
    results = [None] * len(req.urls)
    normal_indices = []

    for i, url in enumerate(req.urls):
        if is_broken_url(url):
            results[i] = PredictionResult(
                url=url, type_code=2, type_name="broken_url", probability=1.0
            )
        else:
            normal_indices.append(i)

    # нормальные URL прогоняем через модель пачкой
    if normal_indices:
        features_list = [make_features(req.urls[i]) for i in normal_indices]
        X = pd.DataFrame(features_list)

        pred_classes = model.predict(X).flatten()
        all_probas = model.predict_proba(X)
        classes_list = list(model.classes_)

        for j, idx in enumerate(normal_indices):
            pc = int(pred_classes[j])
            ci = classes_list.index(pc)
            conf = round(float(all_probas[j][ci]), 4)
            results[idx] = PredictionResult(
                url=req.urls[idx],
                type_code=pc,
                type_name=TYPE_NAMES.get(pc, "unknown"),
                probability=conf,
            )

    return results