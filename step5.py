"""
Шаг 5 (полное обучение): учим модель на ВСЁМ B_labeled.csv и сохраняем её

Что делает скрипт:
  1. читает B_labeled.csv
  2. отделяет признаки от target
  3. делит данные на train/test
  4. обучает CatBoost на всём датасете у меня заняло +- 7 минут
  5. печатает метрики
  6. сохраняет модель в traffic_model_full.cbm
"""

from pathlib import Path

import pandas as pd
from catboost import CatBoostClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent

FILE_DATA = ROOT / "B_labeled.csv"

FILE_MODEL = ROOT / "traffic_model_full.cbm"

df = pd.read_csv(FILE_DATA)
print("всего строк:", len(df))
print("всего колонок:", len(df.columns))

# label — это ответ
# label_name — текстовая версия label, её в обучение не берём

X = df.drop(["label", "label_name"], axis=1)
y = df["label"]

print("признаков для обучения:", X.shape[1])
print("классов:", sorted(y.unique().tolist()))

# 80% учим, 20% проверяем
# stratify=y нужен чтобы доля классов сохранилась в обеих частях

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)

print("Обучающая выборка:", len(X_train))
print("Тестовая выборка: ", len(X_test))

# iterations=700 — датасет большой, можно поставить меньше
# depth=8 — достаточно глубокие деревья для сложных правил
# auto_class_weights='Balanced' — редкие классы не теряются
# eval_set — модель будет видеть качество на тесте во время обучения
# use_best_model=True — сохранит лучшую точку, а не последнюю

model = CatBoostClassifier(
    loss_function="MultiClass",
    eval_metric="Accuracy",
    iterations=100, # Огромный датасет, этого хватит что бы долго не было, но модель не идеальна
    depth=4,
    learning_rate=0.08,
    auto_class_weights="Balanced",
    random_seed=42,
    verbose=100,
    use_best_model=True,
    # task_type="GPU", # если есть видеокарта, коммент убираем
)

model.fit(
    X_train,
    y_train,
    eval_set=(X_test, y_test),
)

y_pred = model.predict(X_test).flatten()

print("\nРезультаты на тестовой выборке")
print("Accuracy:", round(accuracy_score(y_test, y_pred), 4))
print()

target_names = [
    "0 (normal)",
    "1 (DDoS)",
    "2 (PortScan)",
    "3 (Bot)",
    "4 (Infiltration)",
    "5 (Web Attack)",
    "6 (Brute Force)",
    "7 (DoS)",
]

print(classification_report(y_test, y_pred, target_names=target_names))

model.save_model(str(FILE_MODEL))