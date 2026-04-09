"""
UI
"""

import csv
import json
from pathlib import Path

import flet as ft
import requests
from scapy.all import IP, TCP, UDP, rdpcap, sniff

API_URL = "http://localhost:8000"


def show_snack(page, message, color=ft.Colors.BLUE):
    snack = ft.SnackBar(
        content=ft.Text(message),
        bgcolor=color,
        open=True,
    )
    page.show_dialog(snack)
    page.update()


def close_dialog(page):
    if page.dialog is not None:
        page.dialog.open = False
        page.pop_dialog()
    page.update()


def open_help_dialog(page, title, text):
    dialog = ft.AlertDialog(
        title=ft.Text(title),
        content=ft.Text(text),
        actions=[ft.TextButton("Закрыть", on_click=lambda e: close_dialog(page))],
        open=True,
    )
    page.dialog = dialog
    page.show_dialog(dialog)
    page.update()


def fill_url_table(table_control, results):
    table_control.rows.clear()
    for item in results:
        table_control.rows.append(
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text(str(item.get("url", "")))),
                    ft.DataCell(ft.Text(str(item.get("type_code", "")))),
                    ft.DataCell(ft.Text(str(item.get("type_name", "")))),
                    ft.DataCell(ft.Text(str(item.get("probability", "")))),
                ]
            )
        )


def fill_traffic_table(table_control, results):
    table_control.rows.clear()
    for item in results:
        table_control.rows.append(
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text(str(item.get("type_code", "")))),
                    ft.DataCell(ft.Text(str(item.get("type_name", "")))),
                    ft.DataCell(ft.Text(str(item.get("probability", "")))),
                ]
            )
        )


def build_url_result_content(item):
    return ft.Column(
        [
            ft.Text(f"URL: {item.get('url', '')}", selectable=True),
            ft.Text(f"Код класса: {item.get('type_code', '')}"),
            ft.Text(f"Тип: {item.get('type_name', '')}"),
            ft.Text(f"Вероятность: {item.get('probability', '')}"),
        ],
        tight=True,
    )


def build_traffic_result_content(item):
    return ft.Column(
        [
            ft.Text(f"Код класса: {item.get('type_code', '')}"),
            ft.Text(f"Тип: {item.get('type_name', '')}"),
            ft.Text(f"Вероятность: {item.get('probability', '')}"),
        ],
        tight=True,
    )


def extract_urls_from_text_file(path):
    urls = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if line:
            urls.append(line)
    return urls


def extract_urls_from_csv(path):
    import pandas as pd

    df = pd.read_csv(path)
    if "url" not in df.columns:
        raise ValueError("В CSV нет колонки url")

    return [str(x).strip() for x in df["url"].dropna().tolist() if str(x).strip() != ""]


def read_packets_from_file(path):
    return rdpcap(str(path))


def main(page: ft.Page):
    page.title = "UI"
    page.window_width = 1100
    page.window_height = 760
    page.scroll = ft.ScrollMode.AUTO
    page.padding = 20

    last_results = []
    last_combined_url_results = []
    last_combined_traffic_results = []

    # -----------------------------------------------------------------
    # элементы 1 вкладки
    url_input = ft.TextField(
        label="Введите URL",
        hint_text="Например: http://fake-bank-login.com/signin",
        expand=True,
    )

    status_text = ft.Text("", color=ft.Colors.BLUE_GREY_700)
    file_path_input = ft.TextField(
        label="Путь к txt/csv файлу",
        hint_text=r"Например: C:\Users\User\Desktop\Новая папка\urls.txt",
        expand=True,
    )
    traffic_input = ft.TextField(
        label="Введите один flow в JSON",
        hint_text='Например: {"Destination Port": 80, "Flow Duration": 12345}',
        multiline=True,
        min_lines=5,
        max_lines=8,
        expand=True,
    )
    traffic_status_text = ft.Text("", color=ft.Colors.BLUE_GREY_700)
    traffic_file_path_input = ft.TextField(
        label="Путь к csv/pcap файлу",
        hint_text=r"Например: C:\Users\User\Desktop\Новая папка\flows.csv",
        expand=True,
    )
    traffic_result_box = ft.Container(
        content=ft.Text("Здесь будет результат проверки трафика"),
        padding=15,
        border=ft.Border.all(1, ft.Colors.BLUE_GREY_200),
        border_radius=10,
    )
    traffic_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("Код")),
            ft.DataColumn(ft.Text("Тип")),
            ft.DataColumn(ft.Text("Вероятность")),
        ],
        rows=[],
    )
    combined_status_text = ft.Text("", color=ft.Colors.BLUE_GREY_700)
    combined_file_path_input = ft.TextField(
        label="Путь к pcap/pcapng файлу",
        hint_text=r"Например: C:\Users\User\Desktop\Новая папка\dump.pcap",
        expand=True,
    )
    combined_result_box = ft.Container(
        content=ft.Text("Здесь будет совместный результат URL + пакеты"),
        padding=15,
        border=ft.Border.all(1, ft.Colors.BLUE_GREY_200),
        border_radius=10,
    )
    combined_url_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("URL")),
            ft.DataColumn(ft.Text("Код")),
            ft.DataColumn(ft.Text("Тип")),
            ft.DataColumn(ft.Text("Вероятность")),
        ],
        rows=[],
    )
    combined_traffic_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("Код")),
            ft.DataColumn(ft.Text("Тип")),
            ft.DataColumn(ft.Text("Вероятность")),
        ],
        rows=[],
    )
    live_status_text = ft.Text("", color=ft.Colors.BLUE_GREY_700)
    live_counter_text = ft.Text("Собрано пакетов: 0/5", color=ft.Colors.BLUE_GREY_700)
    live_result_box = ft.Container(
        content=ft.Text("Здесь будет результат живого захвата"),
        padding=15,
        border=ft.Border.all(1, ft.Colors.BLUE_GREY_200),
        border_radius=10,
    )
    live_url_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("URL")),
            ft.DataColumn(ft.Text("Код")),
            ft.DataColumn(ft.Text("Тип")),
            ft.DataColumn(ft.Text("Вероятность")),
        ],
        rows=[],
    )
    live_traffic_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("Код")),
            ft.DataColumn(ft.Text("Тип")),
            ft.DataColumn(ft.Text("Вероятность")),
        ],
        rows=[],
    )

    result_box = ft.Container(
        content=ft.Text("Здесь будет результат проверки"),
        padding=15,
        border=ft.Border.all(1, ft.Colors.BLUE_GREY_200),
        border_radius=10,
    )

    table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("URL")),
            ft.DataColumn(ft.Text("Код")),
            ft.DataColumn(ft.Text("Тип")),
            ft.DataColumn(ft.Text("Вероятность")),
        ],
        rows=[],
    )

    def update_table(results):
        fill_url_table(table, results)
        page.update()

    def update_single_result(item):
        result_box.content = build_url_result_content(item)
        page.update()

    def update_traffic_table(results):
        fill_traffic_table(traffic_table, results)
        page.update()

    def update_traffic_single_result(item):
        traffic_result_box.content = build_traffic_result_content(item)
        page.update()

    def update_combined_url_table(results):
        fill_url_table(combined_url_table, results)
        page.update()

    def update_combined_traffic_table(results):
        fill_traffic_table(combined_traffic_table, results)
        page.update()

    def update_live_url_table(results):
        fill_url_table(live_url_table, results)
        page.update()

    def update_live_traffic_table(results):
        fill_traffic_table(live_traffic_table, results)
        page.update()

    def check_one_url(e):
        nonlocal last_results
        url = url_input.value.strip()

        if url == "":
            show_snack(page, "Введите URL", ft.Colors.RED)
            return

        try:
            status_text.value = "Отправка URL в API..."
            page.update()

            response = requests.post(
                f"{API_URL}/url/predict",
                json={"url": url},
                timeout=60,
            )
            response.raise_for_status()

            result = response.json()
            last_results = [result]

            update_single_result(result)
            update_table(last_results)

            status_text.value = "Готово"
            page.update()

        except Exception as ex:
            status_text.value = "Ошибка"
            result_box.content = ft.Text(f"Ошибка: {ex}")
            page.update()

    def save_results(e):
        if not last_results:
            show_snack(page, "Нет результатов для сохранения", ft.Colors.RED)
            return

        save_path = Path("url_results.csv")
        with open(save_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["url", "type_code", "type_name", "probability"],
            )
            writer.writeheader()
            for row in last_results:
                writer.writerow(
                    {
                        "url": row.get("url", ""),
                        "type_code": row.get("type_code", ""),
                        "type_name": row.get("type_name", ""),
                        "probability": row.get("probability", ""),
                    }
                )

        show_snack(page, f"Сохранила в {save_path}", ft.Colors.GREEN)

    def show_help(e):
        open_help_dialog(
            page,
            "Подсказка по файлам",
            "TXT файл:\n"
            "- каждый URL с новой строки\n"
            "- можно 1 URL, можно много\n\n"
            "CSV файл:\n"
            "- обязательно должна быть колонка с названием url\n"
            "- остальные колонки могут быть любыми\n"
            "- из файла будут взяты только значения из колонки url",
        )

    def show_traffic_help(e):
        open_help_dialog(
            page,
            "Подсказка по файлам для трафика",
            "CSV файл:\n"
            "- каждая строка = один сетевой поток\n"
            "- названия колонок должны совпадать с признаками модели\n"
            "- можно передавать не все колонки, отсутствующие будут заполнены нулями\n\n"
            "PCAP файл:\n"
            "- приложение само читает pcap и собирает простые flow-признаки\n"
            "- потом отправляет их в traffic API\n"
            "- лучше всего подходят pcap с IP/TCP/UDP пакетами",
        )

    def show_combined_help(e):
        open_help_dialog(
            page,
            "Подсказка по вкладке 3",
            "Сюда нужно загружать pcap или pcapng файл.\n\n"
            "Что делает вкладка:\n"
            "- ищет в пакетах HTTP URL\n"
            "- собирает flow-признаки из IP/TCP/UDP пакетов\n"
            "- отправляет URL в URL API\n"
            "- отправляет flow в traffic API\n\n"
            "Важно:\n"
            "- полный URL обычно можно извлечь только из обычного HTTP\n"
            "- в HTTPS часто полного URL нет, потому что трафик шифруется\n"
            "- pcapng тоже поддерживается через scapy",
        )

    def extract_http_urls_from_packets(packets):
        urls = []
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                tcp = pkt[TCP]
                if tcp.dport == 80 or tcp.sport == 80:
                    raw_bytes = bytes(tcp.payload)
                    if raw_bytes:
                        try:
                            text = raw_bytes.decode("utf-8", errors="ignore")
                        except Exception:
                            text = ""

                        if text.startswith("GET ") or text.startswith("POST ") or text.startswith("HEAD "):
                            lines = text.split("\r\n")
                            first_line = lines[0] if lines else ""
                            host = ""
                            path_part = ""

                            parts = first_line.split(" ")
                            if len(parts) >= 2:
                                path_part = parts[1]

                            for line in lines:
                                if line.lower().startswith("host:"):
                                    host = line.split(":", 1)[1].strip()
                                    break

                            if host:
                                urls.append(f"http://{host}{path_part}")
        return list(dict.fromkeys(urls))

    def build_flows_from_packets(packets):
        flow_map = {}

        for pkt in packets:
            if IP not in pkt:
                continue

            ip = pkt[IP]
            proto = "OTHER"
            src_port = 0
            dst_port = 0
            flags = ""

            if TCP in pkt:
                proto = "TCP"
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                flags = str(pkt[TCP].flags)
            elif UDP in pkt:
                proto = "UDP"
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)

            key = (ip.src, ip.dst, src_port, dst_port, proto)
            reverse_key = (ip.dst, ip.src, dst_port, src_port, proto)

            pkt_len = len(pkt)
            pkt_time = float(pkt.time)

            if key in flow_map:
                flow = flow_map[key]
                direction = "fwd"
            elif reverse_key in flow_map:
                flow = flow_map[reverse_key]
                direction = "bwd"
            else:
                flow = {
                    "start_time": pkt_time,
                    "end_time": pkt_time,
                    "dst_port": dst_port,
                    "fwd_packets": 0,
                    "bwd_packets": 0,
                    "fwd_lengths": [],
                    "bwd_lengths": [],
                    "all_lengths": [],
                    "times": [],
                    "syn_count": 0,
                    "rst_count": 0,
                    "ack_count": 0,
                    "psh_count": 0,
                    "fin_count": 0,
                    "urg_count": 0,
                    "ece_count": 0,
                }
                flow_map[key] = flow
                direction = "fwd"

            flow["end_time"] = pkt_time
            flow["all_lengths"].append(pkt_len)
            flow["times"].append(pkt_time)

            if direction == "fwd":
                flow["fwd_packets"] += 1
                flow["fwd_lengths"].append(pkt_len)
            else:
                flow["bwd_packets"] += 1
                flow["bwd_lengths"].append(pkt_len)

            if flags:
                if "S" in flags:
                    flow["syn_count"] += 1
                if "R" in flags:
                    flow["rst_count"] += 1
                if "A" in flags:
                    flow["ack_count"] += 1
                if "P" in flags:
                    flow["psh_count"] += 1
                if "F" in flags:
                    flow["fin_count"] += 1
                if "U" in flags:
                    flow["urg_count"] += 1
                if "E" in flags:
                    flow["ece_count"] += 1

        flows = []
        for flow in flow_map.values():
            duration = max(flow["end_time"] - flow["start_time"], 0.000001)
            duration_us = int(duration * 1_000_000)
            total_fwd_bytes = sum(flow["fwd_lengths"])
            total_bwd_bytes = sum(flow["bwd_lengths"])
            total_pkts = flow["fwd_packets"] + flow["bwd_packets"]

            def safe_mean(arr):
                return sum(arr) / len(arr) if arr else 0

            def safe_min(arr):
                return min(arr) if arr else 0

            def safe_max(arr):
                return max(arr) if arr else 0

            def safe_std(arr):
                if len(arr) <= 1:
                    return 0
                m = safe_mean(arr)
                return (sum((x - m) ** 2 for x in arr) / len(arr)) ** 0.5

            all_lengths = flow["all_lengths"]
            all_times = sorted(flow["times"])
            iats = []
            for i in range(1, len(all_times)):
                iats.append((all_times[i] - all_times[i - 1]) * 1_000_000)

            flows.append({
                "Destination Port": flow["dst_port"],
                "Flow Duration": duration_us,
                "Total Fwd Packets": flow["fwd_packets"],
                "Total Backward Packets": flow["bwd_packets"],
                "Total Length of Fwd Packets": total_fwd_bytes,
                "Total Length of Bwd Packets": total_bwd_bytes,
                "Fwd Packet Length Max": safe_max(flow["fwd_lengths"]),
                "Fwd Packet Length Min": safe_min(flow["fwd_lengths"]),
                "Fwd Packet Length Mean": safe_mean(flow["fwd_lengths"]),
                "Fwd Packet Length Std": safe_std(flow["fwd_lengths"]),
                "Bwd Packet Length Max": safe_max(flow["bwd_lengths"]),
                "Bwd Packet Length Min": safe_min(flow["bwd_lengths"]),
                "Bwd Packet Length Mean": safe_mean(flow["bwd_lengths"]),
                "Bwd Packet Length Std": safe_std(flow["bwd_lengths"]),
                "Flow Bytes/s": (total_fwd_bytes + total_bwd_bytes) / duration,
                "Flow Packets/s": total_pkts / duration,
                "Flow IAT Mean": safe_mean(iats),
                "Flow IAT Std": safe_std(iats),
                "Flow IAT Max": safe_max(iats),
                "Flow IAT Min": safe_min(iats),
                "Fwd IAT Total": 0,
                "Fwd IAT Mean": 0,
                "Fwd IAT Std": 0,
                "Fwd IAT Max": 0,
                "Fwd IAT Min": 0,
                "Bwd IAT Total": 0,
                "Bwd IAT Mean": 0,
                "Bwd IAT Std": 0,
                "Bwd IAT Max": 0,
                "Bwd IAT Min": 0,
                "Fwd PSH Flags": flow["psh_count"],
                "Fwd Header Length": 0,
                "Bwd Header Length": 0,
                "Fwd Packets/s": flow["fwd_packets"] / duration,
                "Bwd Packets/s": flow["bwd_packets"] / duration,
                "Min Packet Length": safe_min(all_lengths),
                "Max Packet Length": safe_max(all_lengths),
                "Packet Length Mean": safe_mean(all_lengths),
                "Packet Length Std": safe_std(all_lengths),
                "Packet Length Variance": safe_std(all_lengths) ** 2,
                "FIN Flag Count": flow["fin_count"],
                "SYN Flag Count": flow["syn_count"],
                "RST Flag Count": flow["rst_count"],
                "PSH Flag Count": flow["psh_count"],
                "ACK Flag Count": flow["ack_count"],
                "URG Flag Count": flow["urg_count"],
                "ECE Flag Count": flow["ece_count"],
                "Down/Up Ratio": total_bwd_bytes / total_fwd_bytes if total_fwd_bytes > 0 else 0,
                "Average Packet Size": safe_mean(all_lengths),
                "Avg Fwd Segment Size": safe_mean(flow["fwd_lengths"]),
                "Avg Bwd Segment Size": safe_mean(flow["bwd_lengths"]),
                "Subflow Fwd Packets": flow["fwd_packets"],
                "Subflow Fwd Bytes": total_fwd_bytes,
                "Subflow Bwd Packets": flow["bwd_packets"],
                "Subflow Bwd Bytes": total_bwd_bytes,
                "Init_Win_bytes_forward": 0,
                "Init_Win_bytes_backward": 0,
                "act_data_pkt_fwd": flow["fwd_packets"],
                "min_seg_size_forward": safe_min(flow["fwd_lengths"]),
                "Active Mean": duration_us,
                "Active Std": 0,
                "Active Max": duration_us,
                "Active Min": duration_us,
                "Idle Mean": 0,
                "Idle Std": 0,
                "Idle Max": 0,
                "Idle Min": 0,
            })
        return flows

    def predict_urls(urls):
        if not urls:
            return []
        response = requests.post(
            f"{API_URL}/url/predict_batch",
            json={"urls": urls},
            timeout=180,
        )
        response.raise_for_status()
        return response.json()

    def predict_flows(flows):
        if not flows:
            return []
        response = requests.post(
            f"{API_URL}/traffic/predict_batch",
            json=flows,
            timeout=180,
        )
        response.raise_for_status()
        return response.json()

    def load_file_by_path(e):
        nonlocal last_results
        file_path = file_path_input.value.strip()
        if file_path == "":
            show_snack(page, "Введите путь к файлу", ft.Colors.RED)
            return
        path = Path(file_path)

        if not path.is_file():
            show_snack(page, "Файл не найден", ft.Colors.RED)
            return

        try:
            urls = []

            if path.suffix.lower() == ".txt":
                urls = extract_urls_from_text_file(path)

            elif path.suffix.lower() == ".csv":
                urls = extract_urls_from_csv(path)

            else:
                show_snack(page, "Можно загружать только txt и csv", ft.Colors.RED)
                return

            if not urls:
                show_snack(page, "В файле не найдено URL", ft.Colors.RED)
                return

            status_text.value = f"Загружено URL: {len(urls)}. Отправка в API..."
            page.update()

            last_results = predict_urls(urls)

            if len(last_results) == 1:
                update_single_result(last_results[0])
            else:
                result_box.content = ft.Text(f"Проверено URL: {len(last_results)}")

            update_table(last_results)

            status_text.value = "Готово"
            page.update()

        except Exception as ex:
            status_text.value = "Ошибка"
            result_box.content = ft.Text(f"Ошибка: {ex}")
            page.update()

    def check_one_traffic(e):
        nonlocal last_results
        text = traffic_input.value.strip()

        if text == "":
            show_snack(page, "Введите JSON с признаками потока", ft.Colors.RED)
            return

        try:
            flow = json.loads(text)
            if not isinstance(flow, dict):
                show_snack(page, "Нужно передать один JSON-объект", ft.Colors.RED)
                return

            traffic_status_text.value = "Отправка flow в API..."
            page.update()

            response = requests.post(
                f"{API_URL}/traffic/predict",
                json=flow,
                timeout=60,
            )
            response.raise_for_status()

            result = response.json()
            last_results = [result]

            update_traffic_single_result(result)
            update_traffic_table(last_results)

            traffic_status_text.value = "Готово"
            page.update()

        except Exception as ex:
            traffic_status_text.value = "Ошибка"
            traffic_result_box.content = ft.Text(f"Ошибка: {ex}")
            page.update()

    def save_traffic_results(e):
        if not last_results:
            show_snack(page, "Нет результатов для сохранения", ft.Colors.RED)
            return

        save_path = Path("traffic_results.csv")
        with open(save_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["type_code", "type_name", "probability"],
            )
            writer.writeheader()
            for row in last_results:
                writer.writerow(
                    {
                        "type_code": row.get("type_code", ""),
                        "type_name": row.get("type_name", ""),
                        "probability": row.get("probability", ""),
                    }
                )

        show_snack(page, f"Сохранила в {save_path}", ft.Colors.GREEN)

    def load_traffic_file_by_path(e):
        nonlocal last_results
        file_path = traffic_file_path_input.value.strip()
        if file_path == "":
            show_snack(page, "Введите путь к файлу", ft.Colors.RED)
            return
        path = Path(file_path)

        if not path.is_file():
            show_snack(page, "Файл не найден", ft.Colors.RED)
            return

        try:
            if path.suffix.lower() == ".pcap":
                traffic_status_text.value = "Читаю pcap и собираю потоки..."
                page.update()

                packets = read_packets_from_file(path)
                flows = build_flows_from_packets(packets)

                if not flows:
                    show_snack(page, "В pcap не найдено IP/TCP/UDP пакетов", ft.Colors.RED)
                    return

                traffic_status_text.value = f"Собрано flow из pcap: {len(flows)}. Отправка в API..."
                page.update()

                last_results = predict_flows(flows)

                if len(last_results) == 1:
                    update_traffic_single_result(last_results[0])
                else:
                    traffic_result_box.content = ft.Text(f"Проверено flow: {len(last_results)}")

                update_traffic_table(last_results)
                traffic_status_text.value = "Готово"
                page.update()
                return

            if path.suffix.lower() != ".csv":
                show_snack(page, "Для трафика можно загружать только csv или pcap", ft.Colors.RED)
                return

            import pandas as pd

            df = pd.read_csv(path)
            flows = df.to_dict(orient="records")

            if not flows:
                show_snack(page, "В CSV нет строк", ft.Colors.RED)
                return

            traffic_status_text.value = f"Загружено flow: {len(flows)}. Отправка в API..."
            page.update()

            last_results = predict_flows(flows)

            if len(last_results) == 1:
                update_traffic_single_result(last_results[0])
            else:
                traffic_result_box.content = ft.Text(f"Проверено flow: {len(last_results)}")

            update_traffic_table(last_results)
            traffic_status_text.value = "Готово"
            page.update()

        except Exception as ex:
            traffic_status_text.value = "Ошибка"
            traffic_result_box.content = ft.Text(f"Ошибка: {ex}")
            page.update()

    def load_combined_file(e):
        file_path = combined_file_path_input.value.strip()
        if file_path == "":
            show_snack(page, "Введите путь к pcap/pcapng файлу", ft.Colors.RED)
            return

        path = Path(file_path)
        if not path.is_file():
            show_snack(page, "Файл не найден", ft.Colors.RED)
            return

        if path.suffix.lower() not in [".pcap", ".pcapng"]:
            show_snack(page, "Для вкладки 3 нужен pcap или pcapng", ft.Colors.RED)
            return

        try:
            combined_status_text.value = "Читаю файл и собираю URL/flow..."
            page.update()

            packets = read_packets_from_file(path)
            urls = extract_http_urls_from_packets(packets)
            flows = build_flows_from_packets(packets)

            combined_status_text.value = f"Найдено URL: {len(urls)}, flow: {len(flows)}. Отправка в API..."
            page.update()

            url_results = []
            traffic_results = []

            if urls:
                url_results = predict_urls(urls)
            if flows:
                traffic_results = predict_flows(flows)

            update_combined_url_table(url_results)
            update_combined_traffic_table(traffic_results)

            combined_result_box.content = ft.Column(
                [
                    ft.Text(f"Найдено URL: {len(url_results)}"),
                    ft.Text(f"Найдено flow: {len(traffic_results)}"),
                ],
                tight=True,
            )

            combined_status_text.value = "Готово"
            page.update()

        except Exception as ex:
            combined_status_text.value = "Ошибка"
            combined_result_box.content = ft.Text(f"Ошибка: {ex}")
            page.update()

    def start_live_capture(e):
        nonlocal last_combined_url_results, last_combined_traffic_results
        try:
            live_status_text.value = "Начинаю захват 5 пакетов..."
            live_counter_text.value = "Собрано пакетов: 0/5"
            live_result_box.content = ft.Text("Идёт захват с вашей сети...")
            update_live_url_table([])
            update_live_traffic_table([])
            page.update()

            captured_packets = []

            def on_packet(pkt):
                captured_packets.append(pkt)
                live_counter_text.value = f"Собрано пакетов: {len(captured_packets)}/5"
                page.update()

            sniff(prn=on_packet, count=5, store=True, timeout=30)

            if not captured_packets:
                live_status_text.value = "Ошибка"
                live_result_box.content = ft.Text("Не удалось поймать пакеты за отведённое время")
                page.update()
                return

            live_status_text.value = "Анализирую собранные пакеты..."
            page.update()

            urls = extract_http_urls_from_packets(captured_packets)
            flows = build_flows_from_packets(captured_packets)

            last_combined_url_results = predict_urls(urls) if urls else []
            last_combined_traffic_results = predict_flows(flows) if flows else []

            update_live_url_table(last_combined_url_results)
            update_live_traffic_table(last_combined_traffic_results)

            live_result_box.content = ft.Column(
                [
                    ft.Text(f"Собрано пакетов: {len(captured_packets)}"),
                    ft.Text(f"Найдено URL: {len(last_combined_url_results)}"),
                    ft.Text(f"Найдено flow: {len(last_combined_traffic_results)}"),
                ],
                tight=True,
            )
            live_status_text.value = "Готово"
            page.update()

        except Exception as ex:
            live_status_text.value = "Ошибка"
            live_result_box.content = ft.Text(f"Ошибка: {ex}")
            page.update()

    def show_live_help(e):
        open_help_dialog(
            page,
            "Подсказка по вкладке 4",
            "Эта вкладка захватывает 5 пакетов с вашей текущей сети.\n\n"
            "Что происходит:\n"
            "- нажимаете Старт\n"
            "- приложение ловит 5 пакетов\n"
            "- из них вытаскивает HTTP URL, если они есть\n"
            "- собирает flow-признаки\n"
            "- отправляет данные в обе модели\n\n"
            "Важно:\n"
            "- для захвата пакетов иногда нужны права администратора\n"
            "- если трафика нет, пакеты могут не пойматься за 30 секунд",
        )

    tab1_content = ft.Column(
        [
            ft.Text("Работа с URL", size=24, weight=ft.FontWeight.BOLD),
            ft.Text(
                "Здесь можно проверить один URL вручную или загрузить txt/csv файл.",
                color=ft.Colors.BLUE_GREY_700,
            ),
            ft.Row(
                [
                    url_input,
                    ft.Button("Проверить", on_click=check_one_url),
                ]
            ),
            ft.Row(
                [
                    file_path_input,
                    ft.Button("Открыть файл", on_click=load_file_by_path),
                ]
            ),
            ft.Row(
                [
                    ft.IconButton(
                        icon=ft.Icons.HELP_OUTLINE,
                        tooltip="Подсказка по формату файла",
                        on_click=show_help,
                    ),
                    ft.Button("Сохранить результат", on_click=save_results),
                ]
            ),
            status_text,
            result_box,
            ft.Divider(),
            ft.Text("Результаты", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(content=table, padding=10),
        ],
        tight=True,
    )

    # -----------------------------------------------------------------
    tab2_content = ft.Column(
        [
            ft.Text("Работа с пакетами", size=24, weight=ft.FontWeight.BOLD),
            ft.Text(
                "Здесь можно проверить один flow вручную в JSON или загрузить csv/pcap файл.",
                color=ft.Colors.BLUE_GREY_700,
            ),
            traffic_input,
            ft.Row(
                [
                    ft.Button("Проверить flow", on_click=check_one_traffic),
                ]
            ),
            ft.Row(
                [
                    traffic_file_path_input,
                    ft.Button("Открыть файл", on_click=load_traffic_file_by_path),
                ]
            ),
            ft.Row(
                [
                    ft.IconButton(
                        icon=ft.Icons.HELP_OUTLINE,
                        tooltip="Подсказка по формату файла",
                        on_click=show_traffic_help,
                    ),
                    ft.Button("Сохранить результат", on_click=save_traffic_results),
                ]
            ),
            traffic_status_text,
            traffic_result_box,
            ft.Divider(),
            ft.Text("Результаты", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(content=traffic_table, padding=10),
        ],
        tight=True,
    )

    tab3_content = ft.Column(
        [
            ft.Text("Совместный анализ", size=24, weight=ft.FontWeight.BOLD),
            ft.Text(
                "Загрузка pcap/pcapng файла. Одновременно работают URL-модель и модель пакетов.",
                color=ft.Colors.BLUE_GREY_700,
            ),
            ft.Row(
                [
                    combined_file_path_input,
                    ft.Button("Открыть файл", on_click=load_combined_file),
                ]
            ),
            ft.Row(
                [
                    ft.IconButton(
                        icon=ft.Icons.HELP_OUTLINE,
                        tooltip="Подсказка по формату файла",
                        on_click=show_combined_help,
                    ),
                ]
            ),
            combined_status_text,
            combined_result_box,
            ft.Divider(),
            ft.Text("URL результаты", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(content=combined_url_table, padding=10),
            ft.Divider(),
            ft.Text("Результаты по пакетам", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(content=combined_traffic_table, padding=10),
        ],
        tight=True,
    )

    tab4_content = ft.Column(
        [
            ft.Text("Live-захват", size=24, weight=ft.FontWeight.BOLD),
            ft.Text(
                "Захватить 5 пакетов с вашей сети и сразу отдать их двум моделям.",
                color=ft.Colors.BLUE_GREY_700,
            ),
            ft.Row(
                [
                    ft.Button("Старт", on_click=start_live_capture),
                    ft.IconButton(
                        icon=ft.Icons.HELP_OUTLINE,
                        tooltip="Подсказка по live-захвату",
                        on_click=show_live_help,
                    ),
                ]
            ),
            live_counter_text,
            live_status_text,
            live_result_box,
            ft.Divider(),
            ft.Text("URL результаты", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(content=live_url_table, padding=10),
            ft.Divider(),
            ft.Text("Результаты по пакетам", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(content=live_traffic_table, padding=10),
        ],
        tight=True,
    )

    content_box = ft.Container(content=tab1_content, expand=True)

    def open_tab_1(e):
        content_box.content = tab1_content
        page.update()

    def open_tab_2(e):
        content_box.content = tab2_content
        page.update()

    def open_tab_3(e):
        content_box.content = tab3_content
        page.update()

    def open_tab_4(e):
        content_box.content = tab4_content
        page.update()

    tabs_row = ft.Row(
        [
            ft.Button("URL", on_click=open_tab_1),
            ft.Button("Пакеты", on_click=open_tab_2),
            ft.Button("Совместный анализ", on_click=open_tab_3),
            ft.Button("Live-захват", on_click=open_tab_4),
        ],
        wrap=True,
    )

    page.add(tabs_row, ft.Divider(), content_box)


ft.run(main)