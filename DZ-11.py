# ==============================
# Анализ botsv1.json (WinEventLog + DNS)
# ==============================

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sns.set(style="whitegrid")

with open("botsv1.json", "r", encoding="utf-8") as f:
    data = json.load(f)

print("Общее количество событий:", len(df))
print("Доступные поля:", df.columns.tolist())

# В botsv1 тип лога определяется полем sourcetype
winevent = df[df['sourcetype'].str.contains("WinEventLog", na=False)]
dns = df[df['sourcetype'].str.contains("dns", case=False, na=False)]

print("WinEventLog событий:", len(winevent))
print("DNS событий:", len(dns))

# В botsv1 идентификатор события — поле signature_id
winevent['signature_id'] = pd.to_numeric(winevent['signature_id'], errors='coerce')

# Подозрительные EventID
suspicious_ids = [4625, 4624, 4672, 4720, 4726, 4688, 4703]

winevent_suspicious = winevent[winevent['signature_id'].isin(suspicious_ids)]

winevent_counts = (
    winevent_suspicious['signature_id']
    .value_counts()
    .head(10)
)

print("\nТоп подозрительных WinEventLog событий:")
print(winevent_counts)


plt.figure(figsize=(4,2))
sns.barplot(x=winevent_counts.index.astype(str),
            y=winevent_counts.values)
plt.title("Топ-10 подозрительных WinEventLog событий")
plt.xlabel("EventID")
plt.ylabel("Count")
plt.show()


if "dest" in df.columns:
    top_dest = df["dest"].value_counts().head(10)
    
    plt.figure(figsize=(14, 6))
    sns.barplot(x=top_dest.index, y=top_dest.values)
    plt.title("Топ-10 DNS-адресов/домены (поле dest)", fontsize=16, fontweight="bold")
    plt.xlabel("Адрес/домен")
    plt.ylabel("Количество запросов")
    plt.xticks(rotation=45, ha="right")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
 
    plt.show()
    
    print("\nТоп-10 dest:")
    print(top_dest)
else:
    print("Поле 'dest' не найдено")

print("\nАнализ завершён.")
