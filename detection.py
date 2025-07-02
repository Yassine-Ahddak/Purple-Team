from flask import Flask, request, jsonify, send_file
from datetime import datetime
import csv
import os

app = Flask(__name__)

alerts = []

def generate_html(alerts):
    html_content = """
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Liste des alertes</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; }
            th { background-color: #f2f2f2; }
            h2 { color: #333; }
            .export-button {
                margin: 15px 0;
                display: inline-block;
                padding: 10px 15px;
                background-color: #4CAF50;
                color: white;
                text-decoration: none;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <h2>📋 Liste des alertes reçues</h2>
        <a class="export-button" href="/export-csv" target="_blank">📥 Exporter en CSV</a>
        <table>
            <tr>
                <th>Date/Heure</th>
                <th>Titre</th>
                <th>Technique</th>
                <th>Utilisateur</th>
                <th>Hôte</th>
                <th>CmdLine</th>
                <th>Process Parent</th>
                <th>IP Source</th>
                <th>IP Destination</th>
            </tr>
    """
    for alert in alerts:
        html_content += f"""
            <tr>
                <td>{alert['time']}</td>
                <td>{alert['title']}</td>
                <td>{alert['technique']}</td>
                <td>{alert['user']}</td>
                <td>{alert['host']}</td>
                <td>{alert['cmd_line']}</td>
                <td>{alert['process_parent']}</td>
                <td>{alert['ip_src']}</td>
                <td>{alert['ip_dst']}</td>
            </tr>
        """
    html_content += "</table></body></html>"

    with open("alerts.html", "w", encoding="utf-8") as f:
        f.write(html_content)

@app.route("/alerts-html")
def alerts_html():
    if not os.path.exists("alerts.html"):
        generate_html(alerts)
    return send_file("alerts.html")

@app.route("/export-csv")
def export_csv():
    filename = "alerts.csv"
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
        writer.writeheader()
        writer.writerows(alerts)
    return send_file(filename, as_attachment=True)

@app.route('/splunk-webhook', methods=['POST'])
def receive_webhook():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data received"}), 400

    result = data.get('result', {})
    alert_name = data.get('search_name', 'N/A')

    technique = ''
    if '_' in alert_name:
        parts = alert_name.split('_', 1)
        if parts[0].startswith('T'):
            technique = parts[0]

    raw_time = result.get('_time', '')
    try:
        dt = datetime.fromtimestamp(float(raw_time))
        time_str = dt.strftime('%m-%d-%Y %H:%M:%S')
    except:
        time_str = str(raw_time)

    user = result.get('Nom_du_compte', ['N/A'])[0]
    host = result.get('host', 'N/A')
    cmd_line = result.get('Ligne_de_commande_du_processus', 'N/A')
    ip_src = result.get('ComputerName', 'N/A')
    ip_dst = result.get('DestinationIp', 'N/A')
    process_parent = result.get('Nom du processus créateur', 'N/A')

    alert_entry = {
        'time': time_str,
        'title': alert_name,
        'technique': technique,
        'user': user,
        'host': host,
        'cmd_line': cmd_line,
        'process_parent': process_parent,
        'ip_src': ip_src,
        'ip_dst': ip_dst
    }

    alerts.append(alert_entry)
    generate_html(alerts)

    print("\n=== 🔔 Alerte reçue ===")
    print(f"▶ Titre       : {alert_name}")
    print(f"🕒 Date/Heure : {time_str}")
    print(f"🎯 Technique  : {technique}")
    print("--- Détails ---")
    print(f"👤 Utilisateur : {user}")
    print(f"💻 Hôte        : {host}")
    print(f"🖥️ Cmd Line    : {cmd_line}")
    print(f"⚙️ Process Parent : {process_parent}")
    print(f"🌐 IP Source   : {ip_src}")
    print(f"🎯 IP Dest     : {ip_dst}")

    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    print("🚀 Serveur Flask démarré")
    print("📄 Fichier HTML des alertes : alerts.html")
    print("🌍 Accès Web : http://192.168.5.1:5000/alerts-html")
    print("📥 Export CSV : http://192.168.5.1:5000/export-csv")
    app.run(host='0.0.0.0', port=5000)