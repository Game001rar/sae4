#!/usr/bin/env python3
import csv
import json
import os

CSV_FILENAME = "trafic.csv"
JSON_FILENAME = "extracted_data.json"

def main():
    # 1) Lecture du fichier JSON
    if not os.path.exists(JSON_FILENAME):
        print(f"Le fichier {JSON_FILENAME} est introuvable. Aucune donnée à traiter.")
        return

    with open(JSON_FILENAME, "r", encoding="utf-8") as f:
        traffic_data = json.load(f)

    # 2) Préparation des lignes (A..H = 8 colonnes)
    #    A: timestamp
    #    B: source_ip
    #    C: source_port
    #    D: destination_ip
    #    E: destination_port
    #    F: protocol
    #    G: size
    #    H: flags
    csv_rows = []
    for packet in traffic_data:
        row = [
            packet.get("timestamp", ""),
            packet.get("source_ip", ""),
            packet.get("source_port", ""),
            packet.get("destination_ip", ""),
            packet.get("destination_port", ""),
            packet.get("protocol", ""),
            packet.get("size", 0),
            packet.get("flags", ""),
        ]
        csv_rows.append(row)

    # 3) Lecture du CSV existant (s'il existe)
    existing_lines = []
    if os.path.exists(CSV_FILENAME):
        with open(CSV_FILENAME, "r", encoding="utf-8", newline="") as csvfile:
            existing_lines = list(csv.reader(csvfile))

    # 4) Construction du nouveau contenu
    new_csv_content = []

    # -- a) Conserver la première ligne telle quelle (s'il y en a une)
    if len(existing_lines) > 0:
        new_csv_content.append(existing_lines[0])
    else:
        # Si vous voulez créer vous-même un en-tête si le fichier était vide,
        # vous pouvez le faire ici. Exemple :
        # new_csv_content.append(["timestamp","src_ip","src_port","dst_ip","dst_port","protocol","size","flags"])
        pass

    # -- b) À partir de la 2ᵉ ligne (index 1), on insère ou on remplace les colonnes A..H
    # On parcourt la plus grande taille entre 'existing_lines' (moins la 1re) et 'csv_rows'
    max_lines = max(len(existing_lines) - 1, len(csv_rows))

    for i in range(max_lines):
        # ligne existante n° i+1 (car la 0 est l'entête)
        existing_index = i + 1

        # Récupérer l'existant ou créer une ligne vide
        if existing_index < len(existing_lines):
            row_existing = existing_lines[existing_index]
        else:
            row_existing = []

        # Récupérer la nouvelle ligne de données (si disponible)
        if i < len(csv_rows):
            row_new = csv_rows[i]
        else:
            row_new = []

        # On s'assure que 'row_existing' a suffisamment de colonnes
        # pour éviter l'index out of range sur columns I..Z éventuellement présentes
        if len(row_existing) < 8:
            # Si la ligne existante n'a pas encore 8 colonnes, on complète par des vides
            row_existing.extend([""] * (8 - len(row_existing)))

        # On remplace uniquement A..H (colonnes 0..7) avec row_new
        # S'il n'y a pas de nouvelle valeur, on met vide
        for col_idx in range(8):  # 0..7
            if col_idx < len(row_new):
                row_existing[col_idx] = row_new[col_idx]
            else:
                row_existing[col_idx] = ""

        # On a ainsi mis à jour les 8 premières colonnes,
        # tout ce qui est au-delà (I..Z) reste inchangé
        new_csv_content.append(row_existing)

    # 5) Écriture finale
    with open(CSV_FILENAME, "w", encoding="utf-8", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(new_csv_content)

    print(f"Fichier CSV mis à jour avec succès : {CSV_FILENAME}")

if __name__ == "__main__":
    main()
