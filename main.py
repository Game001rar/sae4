#!/usr/bin/env python3
import re
import markdown2
import yaml
import matplotlib.pyplot as plt
import datetime
import json
import subprocess
from collections import defaultdict

# Lecture de la config YAML dans config.md
with open('config.md', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Extraction du front matter YAML
if lines and lines[0].strip() == '---':
    front_matter_lines = []
    for line in lines[1:]:
        if line.strip() == '---':
            break
        front_matter_lines.append(line)
    config_values = yaml.safe_load(''.join(front_matter_lines))
else:
    config_values = {}

# Récupération des seuils depuis la configuration ou valeurs par défaut
SUSPICIOUS_PACKET_THRESHOLD = config_values.get('suspicious_packet_threshold', 100)
PORT_FREQUENCY_THRESHOLD = config_values.get('port_frequency_threshold', 100)

# Structures de données pour l'analyse
packet_count = 0
protocol_distribution = defaultdict(int)
destination_traffic = defaultdict(int)
source_traffic = defaultdict(int)
traffic_details = []

# Compteurs des ports
source_port_distribution = defaultdict(int)
destination_port_distribution = defaultdict(int)

def detect_protocol(line):
    """Détecte le protocole (TCP/UDP) selon la présence du mot clé 'Flags' (TCP) ou autre logique."""
    return "TCP" if "Flags" in line else "UDP"

def parse_address_and_port(address: str):
    """
    Sépare l'adresse IP du port si présent.
    Exemple : '192.168.0.10.443' -> IP: 192.168.0.10, port: 443
    """
    parts = address.split('.')
    # Si le dernier segment est numérique, on considère que c'est le port
    if parts[-1].isdigit():
        ip = '.'.join(parts[:-1])
        return ip, int(parts[-1])
    else:
        return address, None

def parse_packet_line(line):
    """
    Analyse une ligne de capture type tcpdump et renvoie un dict
    contenant timestamp, IP/port source, IP/port destination, protocole, taille.
    """
    header_pattern = r"^(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+([^\s>]+)\s+>\s+([^\s:]+):"
    match = re.search(header_pattern, line)
    if not match:
        return None

    timestamp, raw_source, raw_destination = match.groups()
    protocol = detect_protocol(line)

    # Extraction IP/port pour la source
    source_ip, source_port = parse_address_and_port(raw_source)
    # Extraction IP/port pour la destination
    destination_ip, destination_port = parse_address_and_port(raw_destination)

    # Extraction de la taille du paquet
    length_match = re.search(r"length\s+(\d+)|\((\d+)\)", line)
    size = int(length_match.group(1) or length_match.group(2) or 0) if length_match else 0

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "size": size
    }

# Demande du fichier à analyser
file_name = input("Entrez le nom du fichier de capture à analyser : ")

try:
    with open(file_name, "r", encoding='utf-8') as file:
        for line in file:
            # On teste si la ligne semble décrire un paquet (commence par HH:MM:SS.fff IP ...)
            if re.match(r"^\d{2}:\d{2}:\d{2}\.\d+\s+IP", line):
                packet = parse_packet_line(line)
                if not packet:
                    continue

                packet_count += 1
                protocol_distribution[packet["protocol"]] += 1
                destination_traffic[packet["destination_ip"]] += 1
                source_traffic[packet["source_ip"]] += 1

                # Comptabiliser ports source/destination
                if packet["source_port"] is not None:
                    source_port_distribution[packet["source_port"]] += 1
                if packet["destination_port"] is not None:
                    destination_port_distribution[packet["destination_port"]] += 1

                traffic_details.append(packet)

except FileNotFoundError:
    print(f"Le fichier '{file_name}' n'a pas été trouvé.")
    exit(1)

print(f"Analyse terminée. Total des paquets traités : {packet_count}")

# -----------------------------------------------------------------------------
# Graphiques : Protocoles et Top 10 destinations
# -----------------------------------------------------------------------------
plt.figure(figsize=(5,4))  # taille plus petite
labels = protocol_distribution.keys()
sizes = protocol_distribution.values()
plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
plt.title('Répartition des protocoles')
plt.savefig('protocol_distribution.png')
plt.close()

top_destinations = sorted(destination_traffic.items(), key=lambda x: x[1], reverse=True)[:10]
if top_destinations:
    dest_labels, dest_values = zip(*top_destinations)
else:
    dest_labels, dest_values = [], []
plt.figure(figsize=(6,4))
plt.bar(dest_labels, dest_values)
plt.xticks(rotation=45, ha='right')
plt.title('Top 10 Destinations par Volume de Trafic')
plt.ylabel('Nombre de paquets')
plt.tight_layout()
plt.savefig('top_destinations.png')
plt.close()

# -----------------------------------------------------------------------------
# Analyse et graphique des ports
# -----------------------------------------------------------------------------
top10_source_ports = sorted(source_port_distribution.items(), key=lambda x: x[1], reverse=True)[:10]
if top10_source_ports:
    sp_labels, sp_values = zip(*top10_source_ports)
else:
    sp_labels, sp_values = [], []

plt.figure(figsize=(6,4))
plt.bar([str(s) for s in sp_labels], sp_values)
plt.xticks(rotation=45, ha='right')
plt.title('Top 10 Ports Source')
plt.ylabel('Nombre de paquets')
plt.tight_layout()
plt.savefig('top_source_ports.png')
plt.close()

top10_dest_ports = sorted(destination_port_distribution.items(), key=lambda x: x[1], reverse=True)[:10]
if top10_dest_ports:
    dp_labels, dp_values = zip(*top10_dest_ports)
else:
    dp_labels, dp_values = [], []

plt.figure(figsize=(6,4))
plt.bar([str(s) for s in dp_labels], dp_values)
plt.xticks(rotation=45, ha='right')
plt.title('Top 10 Ports Destination')
plt.ylabel('Nombre de paquets')
plt.tight_layout()
plt.savefig('top_destination_ports.png')
plt.close()

# Ports suspects (fréquence > seuil)
suspicious_source_ports = {p: c for p, c in source_port_distribution.items() if c > PORT_FREQUENCY_THRESHOLD}
suspicious_destination_ports = {p: c for p, c in destination_port_distribution.items() if c > PORT_FREQUENCY_THRESHOLD}

# -----------------------------------------------------------------------------
# Adresses suspectes
# -----------------------------------------------------------------------------
suspicious_sources = {src: count for src, count in source_traffic.items() if count > SUSPICIOUS_PACKET_THRESHOLD}
suspicious_destinations = {dst: count for dst, count in destination_traffic.items() if count > SUSPICIOUS_PACKET_THRESHOLD}

# Top 10 adresses suspectes (envoi / réception)
top10_sources = sorted(suspicious_sources.items(), key=lambda x: x[1], reverse=True)[:10]
top10_destinations_sus = sorted(suspicious_destinations.items(), key=lambda x: x[1], reverse=True)[:10]
top10_source_addresses = [addr for addr, count in top10_sources]
top10_destination_addresses = [addr for addr, count in top10_destinations_sus]

# Séries temporelles (si vous souhaitez garder ces graphiques)
if traffic_details:
    start_time = datetime.datetime.strptime(traffic_details[0]["timestamp"], "%H:%M:%S.%f")
else:
    start_time = None

send_time_series = {addr: defaultdict(int) for addr in top10_source_addresses}
receive_time_series = {addr: defaultdict(int) for addr in top10_destination_addresses}

for packet in traffic_details:
    if start_time is None:
        continue
    t = datetime.datetime.strptime(packet["timestamp"], "%H:%M:%S.%f")
    rel_sec = (t - start_time).total_seconds()
    sec_bin = int(rel_sec)
    src = packet["source_ip"]
    dst = packet["destination_ip"]
    if src in send_time_series:
        send_time_series[src][sec_bin] += 1
    if dst in receive_time_series:
        receive_time_series[dst][sec_bin] += 1

# Graphique d'envoi - top 10 sources
plt.figure(figsize=(7,4))
for addr in top10_source_addresses:
    times = sorted(send_time_series[addr].keys())
    if not times:
        continue
    counts = [send_time_series[addr][t] for t in times]
    plt.plot(times, counts, label=addr)
plt.xlabel("Temps (secondes depuis le début de la capture)")
plt.ylabel("Nombre de paquets envoyés")
plt.title("Trafic d'Envoi - Top 10 Adresses Sources Suspectes")
plt.legend(loc='upper right', fontsize='small')
plt.tight_layout()
plt.savefig('top10_send_over_time.png')
plt.close()

# Graphique de réception - top 10 destinations
plt.figure(figsize=(7,4))
for addr in top10_destination_addresses:
    times = sorted(receive_time_series[addr].keys())
    if not times:
        continue
    counts = [receive_time_series[addr][t] for t in times]
    plt.plot(times, counts, label=addr)
plt.xlabel("Temps (secondes depuis le début de la capture)")
plt.ylabel("Nombre de paquets reçus")
plt.title("Trafic de Réception - Top 10 Adresses Destinations Suspectes")
plt.legend(loc='upper right', fontsize='small')
plt.tight_layout()
plt.savefig('top10_receive_over_time.png')
plt.close()

# -----------------------------------------------------------------------------
# Génération du rapport Markdown
# -----------------------------------------------------------------------------
md_output = f"""# Rapport de Détection de Trafic Réseau

**Total des paquets traités :** {packet_count}

## Répartition des protocoles
![Protocol Distribution](protocol_distribution.png)

## Top 10 Destinations par Volume de Trafic
![Top Destinations](top_destinations.png)

## Top 10 Ports Source
![Top Ports Source](top_source_ports.png)

## Top 10 Ports Destination
![Top Ports Destination](top_destination_ports.png)

## Adresses Sources Suspectes
"""
if suspicious_sources:
    md_output += "\n| Source | Nombre de paquets |\n|:-------|------------------:|\n"
    for src, count in sorted(suspicious_sources.items(), key=lambda x: x[1], reverse=True):
        md_output += f"| {src} | {count} |\n"
else:
    md_output += "\nAucune adresse source suspecte détectée.\n"

md_output += "\n## Adresses Destinations Suspectes\n"
if suspicious_destinations:
    md_output += "\n| Destination | Nombre de paquets |\n|:------------|------------------:|\n"
    for dst, count in sorted(suspicious_destinations.items(), key=lambda x: x[1], reverse=True):
        md_output += f"| {dst} | {count} |\n"
else:
    md_output += "\nAucune adresse destination suspecte détectée.\n"

md_output += "\n## Ports Sources Suspects\n"
if suspicious_source_ports:
    md_output += "\n| Port Source | Nombre de paquets |\n|:-----------|-------------------:|\n"
    for port, count in sorted(suspicious_source_ports.items(), key=lambda x: x[1], reverse=True):
        md_output += f"| {port} | {count} |\n"
else:
    md_output += "\nAucun port source suspect détecté (selon le seuil).\n"

md_output += "\n## Ports Destination Suspects\n"
if suspicious_destination_ports:
    md_output += "\n| Port Destination | Nombre de paquets |\n|:----------------|--------------------:|\n"
    for port, count in sorted(suspicious_destination_ports.items(), key=lambda x: x[1], reverse=True):
        md_output += f"| {port} | {count} |\n"
else:
    md_output += "\nAucun port destination suspect détecté (selon le seuil).\n"

md_output += f"""\n
## Trafic d'Envoi - Top 10 Adresses Sources Suspectes
![Trafic Envoi Top 10](top10_send_over_time.png)

## Trafic de Réception - Top 10 Adresses Destinations Suspectes
![Trafic Réception Top 10](top10_receive_over_time.png)
"""

with open("rapport_detection.md", "w", encoding='utf-8') as md_file:
    md_file.write(md_output)

print("Le rapport Markdown a été généré dans 'rapport_detection.md'.")
# -----------------------------------------------------------------------------
# Conversion Markdown -> HTML
# -----------------------------------------------------------------------------
html_content = markdown2.markdown(md_output, extras=["tables", "toc", "fenced-code-blocks"])

html_output = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Détection de Trafic Réseau</title>
</head>
<body>
    {html_content}
</body>
</html>
"""

with open("rapport_detection.html", "w", encoding="utf-8") as html_file:
    html_file.write(html_output)

print("Le rapport HTML a été généré dans 'rapport_detection.html'.")
# -----------------------------------------------------------------------------
# Sauvegarde des données dans un JSON (pour le script secondaire)
# -----------------------------------------------------------------------------
with open("extracted_data.json", "w", encoding="utf-8") as json_file:
    json.dump(traffic_details, json_file, ensure_ascii=False, indent=2)

# -----------------------------------------------------------------------------
# Lancement du script secondaire pour générer le CSV
# -----------------------------------------------------------------------------
try:
    subprocess.run(["python3", "generate_csv.py"], check=True)
except subprocess.CalledProcessError:
    print("La commande 'python3' a échoué. Tentative avec 'py'...")
    try:
        subprocess.run(["py", "generate_csv.py"], check=True)
    except subprocess.CalledProcessError:
        print("La commande 'py' a également échoué. Veuillez vérifier votre configuration.")


print("Fin du script principal.")
