"""
Шаг 1: чистим датасет A и вешаем колонку type (класс URL).

type:
  0 - фишинг
  1 - хороший (доверенный популярный домен из goodd.csv ИЛИ просто не попал в плохие списки)
  2 - битая строка / не парсится как нормальный URL
  3 - вредоносное (из URLhaus), если это не помечено как фишинг раньше

файл goodd.csv белый список доменов
- https://tranco-list.eu/ (большая кнопочка скачать)
- https://tranco-list.eu/methodology
файл openphish.txt актуальные фишинговые URL
- https://openphish.com/
- https://openphish.com/phishing_feeds.html (нажимаем free и скачиваем)
файл phishing-domains.txt список доменов, которые были замечены в фишинге
- https://github.com/Phishing-Database/Phishing.Database (ищем последний коммит с phishing-domains...txt и качаем)
файл urlhaus_text_online.txt вредоносное ПО
- https://urlhaus.abuse.ch/
- https://urlhaus.abuse.ch/api/ (Plain-Text URL List - скачивание, нужна регистрация)
"""

from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

ROOT = Path(__file__).resolve().parent

FILE_A = ROOT / "A.csv"
FILE_OUT = ROOT / "A_labeled.csv"
FILE_GOOD_DOMAINS = ROOT / "goodd.csv"

FILE_OPENPHISH = ROOT / "openphish.txt"
FILE_PHISH_DB = ROOT / "phishing-domains.txt"
FILE_URLHAUS = ROOT / "urlhaus_text_online.txt"

TYPE_PHISHING = 0
TYPE_GOOD = 1
TYPE_BROKEN = 2
TYPE_BAD = 3

MAX_LEN_URL = 4096  # слишком длинные строки считаем битыми (дефолт Nginx) можно 8192 (лимит Apache)


def get_host(url):
    """Достаём hostname из строки. Возвращает (host, битая_ли_строка)"""
    if url is None or (isinstance(url, float) and pd.isna(url)):
        return None, True
    s = str(url).strip()
    if s == "" or len(s) > MAX_LEN_URL or "\x00" in s:
        return None, True
    if not s.startswith("http://") and not s.startswith("https://"):
        s = "http://" + s
    try:
        host = urlparse(s).hostname
    except ValueError:
        return None, True
    if not host:
        return None, True
    return host.lower().rstrip("."), False


def host_in_set(host, domain_set):
    """Проверяем домен"""
    parts = host.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in domain_set:
            return True
    return False

# Читаем белый список хороших доменов
good_set = set()
for line in FILE_GOOD_DOMAINS.read_text(encoding="utf-8", errors="replace").splitlines():
    line = line.strip()
    if line == "" or line.startswith("#"):
        continue
    if "," in line:
        dom = line.split(",", 1)[1].strip().lower().rstrip(".")
        if dom:
            good_set.add(dom)
print("хороших доменов:", len(good_set))

# Читаем фишинг-домены
phishing_set = set()

if FILE_OPENPHISH.is_file():
    for line in FILE_OPENPHISH.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue
        if not line.startswith("http://") and not line.startswith("https://"):
            line = "http://" + line
        try:
            h = urlparse(line).hostname
        except ValueError:
            continue
        if h:
            phishing_set.add(h.lower())

if FILE_PHISH_DB.is_file():
    for line in FILE_PHISH_DB.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip().lower().rstrip(".")
        if line == "" or line.startswith("#"):
            continue
        phishing_set.add(line)

if len(phishing_set) == 0:
    raise FileNotFoundError("Нет файлов")

print("фишинг-доменов:", len(phishing_set))

# Читаем вредоносные URL
urlhaus_set = set()

if not FILE_URLHAUS.is_file():
    raise FileNotFoundError("Нет файлов")

for line in FILE_URLHAUS.read_text(encoding="utf-8", errors="replace").splitlines():
    line = line.strip()
    if line == "" or line.startswith("#"):
        continue
    if not line.startswith("http://") and not line.startswith("https://"):
        line = "http://" + line
    try:
        h = urlparse(line).hostname
    except ValueError:
        continue
    if h:
        urlhaus_set.add(h.lower())

print("urlhaus хостов:", len(urlhaus_set))

# Читаем датасет A и чистим
df = pd.read_csv(FILE_A)

# убираем лишнюю колонку индекса
df = df.drop("Unnamed: 0", axis=1)

# выкидываем пустые url и дубли
df = df.dropna(subset=["url"])
df = df.drop_duplicates()

# Ставим type каждому URL
# сначала проверяем битый ли, потом фишинг, потом вредонос, потом хороший
# если нигде не нашли то считаем условно нормальным
types_list = []

for url in df["url"]:
    host, broken = get_host(url)

    if broken:
        types_list.append(TYPE_BROKEN)
        continue

    if host_in_set(host, phishing_set):
        types_list.append(TYPE_PHISHING)
        continue

    if host_in_set(host, urlhaus_set):
        types_list.append(TYPE_BAD)
        continue

    # не попал в плохие
    types_list.append(TYPE_GOOD)

df["type"] = types_list

# Статистика
print("Распределение type:")
names = {0: "фишинг", 1: "хороший", 2: "повреждённые", 3: "плохие"}
for val, cnt in df["type"].value_counts().sort_index().items():
    print(" ", int(val), "(" + names.get(int(val), "?") + "):", cnt)

df.to_csv(FILE_OUT, index=False)