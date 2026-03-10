import json
import time
import requests
import pandas as pd
import matplotlib.pyplot as plt

TELEGRAM_TOKEN = "8630092556:AAEkrtbyFNbPLG4xJjCBSpQuPMkHqMSkIG4"
CHAT_ID = "574556799"


def send_telegram_alert(message):

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"

    payload = {
        "chat_id": CHAT_ID,
        "text": message
    }

    try:
        requests.post(url, data=payload)
    except Exception as e:
        print("Ошибка отправки Telegram:", e)

# ---------- Загрузка логов ----------

logs = []

with open("logs/eve.json", "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            logs.append(json.loads(line))

df_logs = pd.DataFrame(logs)

print("Логи загружены:")
print(df_logs.head())


# ---------- Анализ логов ----------

ip_counts = df_logs["src_ip"].value_counts()

print("\nКоличество событий по IP:")
print(ip_counts)


# ---------- Поиск подозрительных IP ----------

suspicious_ips = ip_counts[ip_counts > 2]

print("\nПодозрительные IP:")

for ip in suspicious_ips.index:
    print(f"Обнаружена подозрительная активность от IP: {ip}")
    print(f"блокировка IP {ip}")


# ---------- Проверка IP через VirusTotal API ----------

API_KEY = "d7f97f2b411644aa2e7b07cec21159c5ad12118b719097593101b33d22bb3022"

vt_url = "https://www.virustotal.com/api/v3/ip_addresses/"
headers = {
    "x-apikey": API_KEY
}

print("\nПроверка IP через VirusTotal:")

for ip in suspicious_ips.index:
    try:
        response = requests.get(vt_url + ip, headers=headers, timeout=15)

        if response.status_code == 200 and response.text:
            data = response.json()

            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]

            print(f"\nIP: {ip}")
            print(f"Malicious detections: {malicious}")

            if malicious > 0:
                print(f" Угроза обнаружена. Блокировка {ip}")

                message = f"Обнаружена угроза!\nIP: {ip}\nMalicious detections: {malicious}"
                send_telegram_alert(message)
            else:
                print("Угроза не обнаружена")

        else:
            print(f"\nIP: {ip}")
            print("Ошибка запроса к VirusTotal:", response.status_code)

    except Exception as e:
        print(f"\nIP: {ip}")
        print("Ошибка при работе с VirusTotal:", e)

    # ограничение API
    time.sleep(15)


# ---------- Запрос к Vulners API ----------

vuln_url = "https://vulners.com/api/v3/search/lucene/"
params = {
    "query": "openssl",
    "size": 5
}

vulnerabilities = []

try:
    response = requests.get(vuln_url, params=params, timeout=15)

    if response.status_code == 200 and response.text:
        data = response.json()

        for item in data.get("data", {}).get("search", []):
            source = item.get("_source", {})
            vulnerabilities.append({
                "id": source.get("id", "unknown"),
                "cvss": source.get("cvss", {}).get("score", 0)
            })

    else:
        print("\nОшибка запроса к Vulners:", response.status_code)

except Exception as e:
    print("\nОшибка при работе с Vulners:", e)

df_vuln = pd.DataFrame(vulnerabilities)

print("\nНайденные уязвимости:")
print(df_vuln)


# ---------- Сохранение отчёта ----------

report = pd.DataFrame({
    "ip": ip_counts.index,
    "events": ip_counts.values
})

report.to_csv("reports/report.csv", index=False)

print("\nОтчёт сохранён: reports/report.csv")


# ---------- Построение графика ----------

ip_counts.plot(kind="bar")

plt.title("Количество событий по IP")
plt.xlabel("IP")
plt.ylabel("Количество событий")

plt.tight_layout()
plt.savefig("charts/ip_chart.png")

print("График сохранён: charts/ip_chart.png")