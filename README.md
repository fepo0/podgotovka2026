# Phishing / Malicious URL And Network Traffic Detection

Проект для обнаружения:

- фишинговых и вредоносных URL;
- подозрительного сетевого трафика;
- аномальной активности в пакетах и потоках;
- подозрительных обращений из `pcap` и `pcapng`.

В проекте есть:

- подготовка датасета URL;
- обучение модели URL;
- API для URL-модели;
- подготовка датасета сетевого трафика;
- обучение модели сетевого трафика;
- API для traffic-модели;
- общий `main.py` как точка входа FastAPI;
- `app.py` на Flet как графический интерфейс.

## Структура проекта

- `step1.py` - разметка датасета `A.csv`
- `step2.py` - обучение модели URL
- `step3.py` - API для URL-модели
- `step4.py` - очистка и алгоритмическая разметка `B1-B8.csv`
- `step5.py` - обучение модели сетевого трафика
- `step6.py` - API для traffic-модели
- `main.py` - общий FastAPI сервер
- `app.py` - Flet UI
- `requirements.txt` - библиотеки проекта

## Логика проекта по шагам

## Шаг 1. `step1.py`

Этот скрипт нужен для подготовки датасета `A.csv`.

Что он делает:

1. читает исходный файл `A.csv`;
2. удаляет пустые значения и дубликаты;
3. берёт внешние списки доменов и URL;
4. алгоритмически ставит каждому URL класс `type`;
5. сохраняет результат в `A_labeled.csv`.

Классы URL:

- `0` - `phishing`
- `1` - `good`
- `2` - `broken_url`
- `3` - `malware`

Какие файлы нужны для шага:

- `A.csv`
- `goodd.csv`
- `openphish.txt`
- `phishing-domains.txt`
- `urlhaus_text_online.txt`

Что получается на выходе:

- `A_labeled.csv`

Когда запускать:

- запускать один раз после подготовки датасета `A.csv` и внешних списков;
- если менялись входные списки или логика разметки, шаг нужно запустить заново.

Команда запуска:

```
python step1.py
```

## Шаг 2. `step2.py`

Этот скрипт обучает модель по датасету URL.

Что он делает:

1. читает `A_labeled.csv`;
2. выкидывает класс `2`, потому что битые URL определяются кодом, а не моделью;
3. превращает URL в набор числовых признаков;
4. делит данные на train/test;
5. обучает `CatBoostClassifier`;
6. считает метрики;
7. сохраняет модель в `url_model.cbm`.

Основные признаки URL:

- длина URL;
- длина домена;
- длина пути;
- число точек;
- число дефисов;
- число `@`;
- число поддоменов;
- число цифр;
- доля цифр;
- доля букв;
- наличие HTTPS;
- наличие IP вместо домена;
- наличие специальных символов.

Что получается на выходе:

- `url_model.cbm`

```
python step2.py
```

## Шаг 3. `step3.py`

Что делает:

1. загружает `url_model.cbm`;
2. проверяет, не является ли URL битым;
3. если URL битый, сразу возвращает класс `2`;
4. если URL нормальный, строит признаки и отправляет их в модель;
5. возвращает класс и вероятность.

Что важно:

Роуты из `step3.py`:

- `POST /url/predict`
- `POST /url/predict_batch`

## Шаг 4. `step4.py`

Этот скрипт подготавливает сетевой датасет `B1-B8.csv`.

Что он делает:

1. читает файлы `B1.csv` ... `B8.csv`;
2. удаляет мусорные и бесполезные колонки;
3. приводит значения к числам;
4. удаляет `NaN`, `inf` и дубликаты;
5. по набору правил алгоритмически назначает каждой строке класс `label`;
6. сохраняет общий файл `B_labeled.csv`.

Каждая строка здесь - это один сетевой поток.

Классы traffic-модели:

- `0` - `normal`
- `1` - `DDoS`
- `2` - `PortScan`
- `3` - `Bot`
- `4` - `Infiltration`
- `5` - `Web Attack`
- `6` - `Brute Force`
- `7` - `DoS`

Как работает разметка:

- `PortScan` - короткий поток, SYN, мало пакетов и мало данных;
- `DDoS` - очень высокая скорость пакетов, много пакетов, короткий поток;
- `DoS` - высокая скорость байтов, но не такой короткий поток;
- `Brute Force` - подозрительный поток на портах `21` и `22`;
- `Web Attack` - HTTP/HTTPS порты и аномально много данных от клиента;
- `Bot` - регулярные интервалы, долгий поток, умеренный трафик;
- `Infiltration` - очень длинный поток и мало пакетов;
- всё остальное считается `normal`.

Что получается на выходе:

- `B_labeled.csv`

Команда запуска:

```
python step4.py
```

## Шаг 5. `step5.py`

Этот скрипт обучает модель по размеченному сетевому датасету.

Что он делает:

1. читает `B_labeled.csv`;
2. отделяет признаки от `label` и `label_name`;
3. делит данные на train/test;
4. обучает `CatBoostClassifier`;
5. считает метрики;
6. сохраняет модель в `traffic_model_full.cbm`.

Что получается на выходе:

- `traffic_model_full.cbm`

Команда запуска:

```
python step5.py
```

## Шаг 6. `step6.py`

Этот файл нужен для использования модели сетевого трафика через API.

Что он делает:

1. пытается загрузить `traffic_model_full.cbm`;
2. если полного файла нет, берёт `traffic_model.cbm`;
3. принимает JSON с признаками потока;
4. собирает признаки в правильном порядке;
5. отдаёт класс и вероятность.

Роуты из `step6.py`:

- `POST /traffic/predict`
- `POST /traffic/predict_batch`

## Как работает `main.py`

`main.py` - это главная точка входа API.

Что он делает:

1. создаёт объект `FastAPI`;
2. подключает роуты из `step3.py`;
3. подключает роуты из `step6.py`;
4. запускает сервер `uvicorn`.

После запуска доступны:

- Swagger UI: http://localhost:8000/docs
- OpenAPI JSON: http://localhost:8000/openapi.json

Команда запуска:

```
python main.py
```

## Как работает `app.py`

`app.py` - это графический интерфейс на `Flet`.

Перед запуском `app.py` нужно сначала запустить `main.py`.

Команда запуска:

```
python app.py
```

В приложении есть 4 вкладки.

### Вкладка 1. URL

Что умеет:

- проверить один URL вручную;
- загрузить `txt` или `csv`;
- отправить URL в API;
- показать тип и вероятность;
- сохранить результат в `url_results.csv`.

Форматы файлов:

- `txt` - один или много URL, каждый с новой строки;
- `csv` - обязательно должна быть колонка `url`.

### Вкладка 2. Пакеты

Что умеет:

- принять один flow в виде JSON;
- загрузить `csv` с потоками;
- загрузить `pcap`;
- из `pcap` собрать признаки потока;
- отправить данные в traffic API;
- сохранить результат в `traffic_results.csv`.

### Вкладка 3. Совместный анализ

Что умеет:

- загрузить `pcap` или `pcapng`;
- вытащить из обычного HTTP URL;
- собрать flow-признаки из пакетов;
- отправить URL в URL API;
- отправить потоки в traffic API;
- показать результаты сразу от двух моделей.

### Вкладка 4. Live-захват

Что умеет:

- захватить 5 пакетов с текущей сети;
- показывать прогресс захвата;
- вытащить HTTP URL, если они есть;
- собрать flow-признаки;
- отправить данные сразу в обе модели;
- показать результаты по URL и по traffic.

Важно:

- для live-захвата на Windows могут понадобиться права администратора;


## Установка библиотек

Установка из `requirements.txt`:

```
pip install -r requirements.txt
```

Если нужно собрать список библиотек из текущего окружения:

```
pip freeze > requirements.txt
```

## API проекта

Общий адрес API:

- `http://localhost:8000`

Документация:

- Swagger UI: http://localhost:8000/docs
- OpenAPI JSON: http://localhost:8000/openapi.json

## URL API

### `POST /url/predict`

Проверка одного URL.

Пример запроса:

```json
{
  "url": "http://example.com/login"
}
```

Пример ответа:

```json
{
  "url": "http://example.com/login",
  "type_code": 1,
  "type_name": "benign",
  "probability": 0.9821
}
```

### `POST /url/predict_batch`

Проверка списка URL.

Пример запроса:

```json
{
  "urls": [
    "http://example.com",
    "https://fake-bank-login.com/auth",
    "broken_url_text"
  ]
}
```

Пример ответа:

```json
[
  {
    "url": "http://example.com",
    "type_code": 1,
    "type_name": "benign",
    "probability": 0.9912
  },
  {
    "url": "https://fake-bank-login.com/auth",
    "type_code": 0,
    "type_name": "phishing",
    "probability": 0.9987
  },
  {
    "url": "broken_url_text",
    "type_code": 2,
    "type_name": "broken_url",
    "probability": 1.0
  }
]
```

Классы URL:

- `0` - `phishing`
- `1` - `benign`
- `2` - `broken_url`
- `3` - `malware`

## Traffic API

### `POST /traffic/predict`

Проверка одного потока.

Пример запроса:

```json
{
  "Destination Port": 80,
  "Flow Duration": 15000,
  "Total Fwd Packets": 10,
  "Total Backward Packets": 8,
  "Total Length of Fwd Packets": 1200,
  "Total Length of Bwd Packets": 5600
}
```

- можно передавать не все 67 признаков;
- отсутствующие поля сервер заполнит нулями;
- признаки будут собраны в нужном порядке внутри `step6.py`.

Пример ответа:

```json
{
  "flow": {
    "Destination Port": 80,
    "Flow Duration": 15000,
    "Total Fwd Packets": 10,
    "Total Backward Packets": 8,
    "Total Length of Fwd Packets": 1200,
    "Total Length of Bwd Packets": 5600
  },
  "type_code": 5,
  "type_name": "Web Attack",
  "probability": 0.8732
}
```

### `POST /traffic/predict_batch`

Проверка списка потоков.

Пример запроса:

```json
[
  {
    "Destination Port": 80,
    "Flow Duration": 15000,
    "Total Fwd Packets": 10
  },
  {
    "Destination Port": 22,
    "Flow Duration": 9000,
    "Total Fwd Packets": 18
  }
]
```

Пример ответа:

```json
[
  {
    "flow": {
      "Destination Port": 80,
      "Flow Duration": 15000,
      "Total Fwd Packets": 10
    },
    "type_code": 5,
    "type_name": "Web Attack",
    "probability": 0.8732
  },
  {
    "flow": {
      "Destination Port": 22,
      "Flow Duration": 9000,
      "Total Fwd Packets": 18
    },
    "type_code": 6,
    "type_name": "Brute Force",
    "probability": 0.9114
  }
]
```

Классы traffic:

- `0` - `normal`
- `1` - `DDoS`
- `2` - `PortScan`
- `3` - `Bot`
- `4` - `Infiltration`
- `5` - `Web Attack`
- `6` - `Brute Force`
- `7` - `DoS`

## Результаты моделей

## Результаты URL-модели

URL-модель обучается в `step2.py` на основе `A_labeled.csv`.

Модель:

- `CatBoostClassifier`

Что делает хорошо:

- различает фишинг, нормальные URL и вредоносные URL;
- работает быстро;
- умеет отдавать вероятность;
- битые URL отдельно обрабатываются кодом, без ML.

## Результаты traffic-модели

Traffic-модель обучалась в `step5.py` по `B_labeled.csv`.

По последнему запуску:

- `bestTest = 0.993904055`
- `bestIteration = 96`
- `Accuracy = 0.9727`

Отчёт по классам:

```text
                  precision    recall  f1-score   support

      0 (normal)       1.00      0.97      0.98    465394
        1 (DDoS)       0.88      1.00      0.94       294
    2 (PortScan)       0.80      1.00      0.89      8626
         3 (Bot)       0.21      0.99      0.35      1366
4 (Infiltration)       0.35      1.00      0.52       629
  5 (Web Attack)       0.89      1.00      0.94     33969
 6 (Brute Force)       0.95      1.00      0.97      2953
         7 (DoS)       0.49      1.00      0.66      1288
```

Краткий вывод:

- модель очень хорошо находит атаки по `recall`;
- лучше всего распознаются `normal`, `DDoS`, `PortScan`, `Web Attack`, `Brute Force`;
- по `Bot`, `Infiltration` и `DoS` модель часто даёт ложные срабатывания;