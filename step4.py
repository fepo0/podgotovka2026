"""
Шаг 4: чистим датасеты B1-B8 и алгоритмом проставляем label
каждой строке по её сетевым характеристикам

Каждая строка = один сетевой поток
Поток = набор пакетов между двумя устройствами за одну сессию.

Оставляем 67 колонок:

Destination Port             - порт назначения
Flow Duration                - длительность потока в микросекундах
Total Fwd Packets            - сколько пакетов отправил клиент
Total Backward Packets       - сколько пакетов вернул сервер
Total Length of Fwd Packets  - суммарный размер данных от клиента
Total Length of Bwd Packets  - суммарный размер данных от сервера
Fwd Packet Length Max        - самый большой пакет от клиента
Fwd Packet Length Min        - самый маленький пакет от клиента
Fwd Packet Length Mean       - средний размер пакета от клиента
Fwd Packet Length Std        - разброс размеров пакетов от клиента
Bwd Packet Length Max        - самый большой пакет от сервера
Bwd Packet Length Min        - самый маленький пакет от сервера
Bwd Packet Length Mean       - средний размер пакета от сервера
Bwd Packet Length Std        - разброс размеров пакетов от сервера
Flow Bytes/s                 - скорость потока (байт в секунду)
Flow Packets/s               - скорость потока (пакетов в секунду)
Flow IAT Mean                - среднее время между пакетами (Inter-Arrival Time)
Flow IAT Std                 - разброс времени между пакетами
Flow IAT Max                 - максимальная пауза между пакетами
Flow IAT Min                 - минимальная пауза между пакетами
Fwd IAT Total                - суммарное время между пакетами от клиента
Fwd IAT Mean                 - среднее время между пакетами от клиента
Fwd IAT Std                  - разброс времени между пакетами от клиента
Fwd IAT Max                  - максимальная пауза от клиента
Fwd IAT Min                  - минимальная пауза от клиента
Bwd IAT Total                - суммарное время между пакетами от сервера
Bwd IAT Mean                 - среднее время между пакетами от сервера
Bwd IAT Std                  - разброс времени между пакетами от сервера
Bwd IAT Max                  - максимальная пауза от сервера
Bwd IAT Min                  - минимальная пауза от сервера
Fwd PSH Flags                - сколько раз клиент поставил флаг PSH
Fwd Header Length            - суммарный размер TCP-заголовков от клиента
Bwd Header Length            - суммарный размер TCP-заголовков от сервера
Fwd Packets/s                - скорость отправки пакетов клиентом
Bwd Packets/s                - скорость отправки пакетов сервером
Min Packet Length            - самый маленький пакет во всём потоке
Max Packet Length            - самый большой пакет во всём потоке
Packet Length Mean           - средний размер пакета во всём потоке
Packet Length Std            - разброс размеров пакетов во всём потоке
Packet Length Variance       - дисперсия размеров пакетов
FIN Flag Count               - флаг FIN (завершение соединения)
SYN Flag Count               - флаг SYN (начало соединения)
RST Flag Count               - флаг RST (сброс соединения)
PSH Flag Count               - флаг PSH (передай данные сразу)
ACK Flag Count               - флаг ACK (подтверждение)
URG Flag Count               - флаг URG (срочные данные)
ECE Flag Count               - флаг ECE (контроль перегрузки)
Down/Up Ratio                - соотношение скачивание/отправка
Average Packet Size          - средний размер пакета
Avg Fwd Segment Size         - средний размер сегмента от клиента
Avg Bwd Segment Size         - средний размер сегмента от сервера
Subflow Fwd Packets          - пакеты в подпотоке от клиента
Subflow Fwd Bytes            - байты в подпотоке от клиента
Subflow Bwd Packets          - пакеты в подпотоке от сервера
Subflow Bwd Bytes            - байты в подпотоке от сервера
Init_Win_bytes_forward       - размер TCP-окна клиента при установке соединения
Init_Win_bytes_backward      - размер TCP-окна сервера при установке соединения
act_data_pkt_fwd             - пакеты с данными от клиента (не пустые)
min_seg_size_forward         - минимальный размер сегмента от клиента
Active Mean                  - среднее время активности потока
Active Std                   - разброс времени активности
Active Max                   - максимальное время активности
Active Min                   - минимальное время активности
Idle Mean                    - среднее время простоя потока
Idle Std                     - разброс времени простоя
Idle Max                     - максимальное время простоя
Idle Min                     - минимальное время простоя

Удалённые колонки:
  Fwd Header Length.1         - дубликат Fwd Header Length
  Fwd/Bwd URG Flags           - всегда 0
  Bwd PSH Flags               - всегда 0
  CWE Flag Count              - всегда 0
  Fwd/Bwd Avg Bytes/Bulk, Packets/Bulk, Bulk Rate (6 шт) - всегда 0

Классы:
  0 - normal
  https://www.unb.ca/cic/datasets/ids-2017.html
  https://fkie-cad.github.io/COMIDDS/content/datasets/cic_ids2017/
  1 - DDoS
  https://izv.etu.ru/ru/arhive/2024-t.-17/t.-17-n-8/65-80
  https://www.nature.com/articles/s41598-024-66907-z
  2 - PortScan
  https://thecyberfort.net/identifying-nmap-scanning-techniques-with-wireshark/
  https://phb-crystal-ball.org/detect-port-scans-with-ebpf/
  3 - Bot
  https://networkthreatdetection.com/analyzing-c2-beaconing-patterns/
  https://www.netskope.com/resources/white-papers/effective-c2-beaconing-detection-white-paper
  4 - Infiltration
  https://sec.co/blog/detecting-data-exfiltration-without-false-positives
  5 - Web Attack
  https://research.splunk.com/web/e0aad4cf-0790-423b-8328-7564d0d938f9/
  https://www.blackhillsinfosec.com/bypassing-wafs-using-oversized-requests/
  https://www.sciencedirect.com/science/article/pii/S221421262400173X
  6 - Brute Force
  https://ieeexplore.ieee.org/document/9118459
  7 - DoS
  https://blog.securelayer7.net/dos-vs-ddos-attacks/
  https://www.cloudflare.com/ru-ru/learning/ddos/ddos-attack-tools/slowloris/
  https://www.cloudflare.com/ru-ru/learning/ddos/ddos-low-and-slow-attack/
"""

import numpy as np
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parent

B_FILES = [f"B{i}.csv" for i in range(1, 9)]

DROP_COLS = [
    "Fwd Header Length.1",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Bwd PSH Flags",
    "CWE Flag Count",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
]

LABEL_NAMES = {
    0: "normal",
    1: "DDoS",
    2: "PortScan",
    3: "Bot",
    4: "Infiltration",
    5: "Web Attack",
    6: "Brute Force",
    7: "DoS",
}

parts = []
for filename in B_FILES:
    print(f"{filename}...", end=" ")
    df = pd.read_csv(ROOT / filename, on_bad_lines="skip", encoding="utf-8")
    df.columns = df.columns.str.strip()
    for col in DROP_COLS:
        if col in df.columns:
            df = df.drop(col, axis=1)
    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    df = df.drop_duplicates()
    print(f"{len(df)} строк")
    parts.append(df)

df = pd.concat(parts, ignore_index=True)
print(f"Общий датасет: {len(df)} строк, {len(df.columns)} колонок")

# Берем самые быстрые
pkt_rate_95 = df["Flow Packets/s"].quantile(0.95)
byte_rate_90 = df["Flow Bytes/s"].quantile(0.90)
# длительность 10%
duration_10 = df["Flow Duration"].quantile(0.10)
# очень долгий
duration_90 = df["Flow Duration"].quantile(0.90)
# типичные пакеты
fwd_pkt_mean = df["Total Fwd Packets"].median()
# маленькие
avg_pkt_size_10 = df["Average Packet Size"].quantile(0.10)

# сверху не ставим конкретный показатель, а берем все показатели и берем все что выше указанного процента от общего

print(f"Порог скорости пакетов (95%): {pkt_rate_95:.1f} пак/сек")
print(f"Порог скорости байтов (90%): {byte_rate_90:.1f} байт/сек")
print(f"Короткий поток (10%): {duration_10:.0f} мкс")
print(f"Длинный поток (90%): {duration_90:.0f} мкс")

# Правила основаны на известных признаках сетевых атак
# PortScan: SYN-флаги + очень мало данных + мало пакетов (зондирование портов)
# DDoS: бешеная скорость пакетов + много пакетов + короткий поток
# DoS: высокая скорость байтов + более длинный чем DDoS
# Brute Force: порт 21 (FTP) или 22 (SSH) + много пакетов (перебор паролей)
# Web Attack: порт 80/443/8080 + необычно много данных от клиента
# Bot: регулярные интервалы (маленький разброс IAT) + долгий поток
# Infiltration: очень длинный поток + мало пакетов (тихое проникновение)
# Normal: всё остальное

labels = np.zeros(len(df), dtype=int)  # по умолчанию 0 = normal

port = df["Destination Port"].values
duration = df["Flow Duration"].values
fwd_pkts = df["Total Fwd Packets"].values
bwd_pkts = df["Total Backward Packets"].values
total_pkts = fwd_pkts + bwd_pkts
fwd_len = df["Total Length of Fwd Packets"].values
bwd_len = df["Total Length of Bwd Packets"].values
pkt_rate = df["Flow Packets/s"].values
byte_rate = df["Flow Bytes/s"].values
syn_flag = df["SYN Flag Count"].values
rst_flag = df["RST Flag Count"].values
avg_pkt = df["Average Packet Size"].values
iat_std = df["Flow IAT Std"].values
iat_mean = df["Flow IAT Mean"].values
fwd_pkt_max = df["Fwd Packet Length Max"].values

# Правило 1: PortScan
is_portscan = (
    (syn_flag > 0) &
    (total_pkts <= 4) &
    (fwd_len + bwd_len < 100) &
    (duration < duration_10)
)
labels[is_portscan] = 2

# Правило 2: DDoS
# бешеная скорость + много пакетов + короткие потоки
is_ddos = (
    (labels == 0) &
    (pkt_rate > pkt_rate_95) &
    (total_pkts > 10) &
    (duration < duration_90) &
    (avg_pkt < 200)
)
labels[is_ddos] = 1

# Правило 3: DoS
# высокая скорость байтов + не суперкороткий
is_dos = (
    (labels == 0) &
    (byte_rate > byte_rate_90) &
    (total_pkts > 5) &
    (fwd_pkts > 2) &
    (duration > duration_10)
)
labels[is_dos] = 7

# Правило 4: Brute Force
# порт SSH(22) или FTP(21), много пакетов
is_bruteforce = (
    (labels == 0) &
    ((port == 21) | (port == 22)) &
    (total_pkts > 5) &
    (fwd_pkts > 2)
)
labels[is_bruteforce] = 6

# Правило 5: Web Attack
# HTTP-порты + аномально много данных от клиента
fwd_len_p90 = np.quantile(fwd_len[fwd_len > 0], 0.90) if (fwd_len > 0).any() else 1000
is_webattack = (
    (labels == 0) &
    ((port == 80) | (port == 443) | (port == 8080) | (port == 8443)) &
    (fwd_len > fwd_len_p90) &
    (fwd_pkts > 5)
)
labels[is_webattack] = 5

# Правило 6: Bot
# регулярные интервалы (маленький разброс) + средний/длинный поток + умеренный трафик
iat_std_50 = df["Flow IAT Std"].quantile(0.50)
duration_50 = df["Flow Duration"].quantile(0.50)
is_bot = (
    (labels == 0) &
    (duration > duration_50) &
    (iat_std < iat_std_50) &
    (iat_std > 0) &
    (total_pkts >= 3) &
    (total_pkts < 200) &
    (avg_pkt < 500)
)
labels[is_bot] = 3

# Правило 7: Infiltration
# очень долгий поток + мало пакетов
duration_97 = df["Flow Duration"].quantile(0.97)
is_infiltration = (
    (labels == 0) &
    (duration > duration_97) &
    (total_pkts <= 10) &
    (fwd_len + bwd_len < 5000)
)
labels[is_infiltration] = 4

# всё что не попало ни в одно правило = normal (0)

df["label"] = labels
df["label_name"] = df["label"].map(LABEL_NAMES)

# Статистика
print("\nРаспределение классов:")
for code in sorted(LABEL_NAMES.keys()):
    name = LABEL_NAMES[code]
    count = (labels == code).sum()
    pct = count / len(labels) * 100
    print(f"{code} ({name}): {count}")


out_path = ROOT / "B_labeled.csv"
df.to_csv(out_path, index=False)