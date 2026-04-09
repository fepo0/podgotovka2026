"""
Шаг 2: генерируем признаки из URL, обучаем модель CatBoost и сохраняем её.

На входе: A_labeled.csv
На выходе: url_model.cbm (файл модели, можно потом загрузить и предсказывать)

Почему CatBoost:
  - из коробки хорошо работает без долгой настройки (в отличие от XGBoost где надо подбирать параметры)
  - умеет сам балансировать классы
  - быстро обучается на таких объёмах! (у меня заняло +- 11 минут)
  - встроенное сохранение/загрузка модели одной строкой
"""

import re
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
from catboost import CatBoostClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent

FILE_LABELED = ROOT / "A_labeled.csv"

FILE_MODEL = ROOT / "url_model.cbm"

# Модель не умеет читать текст — ей нужны числа.
# Поэтому из каждого URL мы вытаскиваем числовые характеристики

def make_features(url):
    """Из одной строки URL делаем словарь с числовыми признаками"""

    s = str(url).strip()

    # если URL без схемы, то добавляем http://
    full = s if s.startswith("http://") or s.startswith("https://") else "http://" + s

    try:
        parsed = urlparse(full)
    except ValueError:
        # Домен.invalid — это специальная зона, которая по стандарту RFC 2606 гарантированно не существует в интернете
        # Она предназначена для таких случаев
        parsed = urlparse("http://broken.invalid")

    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # считаем количество поддоменов
    parts = host.split(".")
    subdomain_count = max(len(parts) - 2, 0)

    # чем больше цифр, тем подозрительнее
    digit_count = sum(c.isdigit() for c in s)
    digit_ratio = digit_count / max(len(s), 1)

    # доля букв
    letter_count = sum(c.isalpha() for c in s)
    letter_ratio = letter_count / max(len(s), 1)

    features = {
        "url_length":        len(s),                                                        # общая длина строки
        "host_length":       len(host),                                                     # длина домена
        "path_length":       len(path),                                                     # длина домена
        "query_length":      len(query),                                                    # длина параметров после ?
        "dot_count":         s.count("."),                                                  # сколько точек во всём URL
        "dash_count":        s.count("-"),                                                  # сколько дефисов
        "at_count":          s.count("@"),                                                  # сколько @
        "subdomain_count":   subdomain_count,                                               # сколько поддоменов
        "digit_count":       digit_count,                                                   # сколько цифр
        "digit_ratio":       round(digit_ratio, 4),                                         # доля цифр от длины
        "letter_ratio":      round(letter_ratio, 4),                                        # доля букв от длины
        "is_https":          int(s.startswith("https://")),                                 # есть ли https
        "has_at":            int("@" in s),                                                 # есть ли @
        "has_double_slash":  int("//" in s.split("://", 1)[-1]),               # есть ли // после схемы
        "has_ip":            int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))),  # вместо домена IP-адрес
        "special_chars":     len(re.findall(r"[^a-zA-Z0-9./:?&=_\-]", s)),           # сколько странных символов
        "fragment_length":   len(parsed.fragment or ""),                                    # длина части после #
    }
    return features

df = pd.read_csv(FILE_LABELED)
print("всего строк:", len(df))

# битые URL мы и так можем ловить кодом, поэтому просто выкидываем
df = df[df["type"] != 2].reset_index(drop=True)

# генерируем признаки для каждого URL
features_list = []
for url in df["url"]:
    features_list.append(make_features(url))

# превращаем список словарей в таблицу
X = pd.DataFrame(features_list)
y = df["type"]

print("признаков:", X.shape[1])
print("названия:", list(X.columns))

# 80% — учим, 20% — проверяем
# stratify=y — чтобы в обоих частях было одинаковое соотношение классов
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Обучающая выборка: {len(X_train)} строк")
print(f"Тестовая выборка:  {len(X_test)} строк")

# auto_class_weights='Balanced' — модель сама даст больший вес редким классам (фишинг, плохие),
# чтобы не игнорировать их на фоне «хороших»
# iterations=1000 — сколько деревьев строить (больше = точнее, но дольше)
# depth=8 — глубина каждого дерева
# learning_rate — скорость обучения, 0.1 это стандартное хорошее значение
# verbose=100 — печатать прогресс каждые 100 итераций

model = CatBoostClassifier(
    iterations=1000,
    depth=8,
    learning_rate=0.1,
    auto_class_weights="Balanced",
    random_seed=42,
    verbose=100,
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("\n=== Результаты на тестовой выборке ===")
print("Accuracy:", round(accuracy_score(y_test, y_pred), 4))
print()

target_names = ["0 (фишинг)", "1 (хороший)", "3 (плохие)"]
print(classification_report(y_test, y_pred, target_names=target_names))

model.save_model(str(FILE_MODEL))