import sqlite3
import xml.etree.ElementTree as ET
import os
from flask import Flask, request, render_template, jsonify

def create_database(db_path):
    """Creates the SQLite database with the required schema."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        fqdn TEXT,
        os TEXT,
        credentialed_scan TEXT,
        start_time TEXT,
        end_time TEXT
    );
    
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER,
        plugin_id INTEGER,
        plugin_name TEXT,
        severity INTEGER,
        description TEXT,
        solution TEXT,
        FOREIGN KEY (host_id) REFERENCES hosts(id)
    );
    
    CREATE TABLE IF NOT EXISTS open_ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER,
        port INTEGER,
        protocol TEXT,
        service TEXT,
        state TEXT,
        FOREIGN KEY (host_id) REFERENCES hosts(id)
    );
    
    CREATE VIEW view_ports AS
    SELECT hosts.id, hosts.ip, open_ports.port, open_ports.protocol, open_ports.service
    FROM hosts
    INNER JOIN open_ports ON open_ports.host_id = hosts.id
    WHERE NOT open_ports.port == 0;
    
    CREATE VIEW vuln_instances AS
    SELECT plugin_name, COUNT(*) AS count, 
           CASE 
               WHEN severity = 1 THEN 'Low'
               WHEN severity = 2 THEN 'Medium'
               WHEN severity = 3 THEN 'High'
               WHEN severity = 4 THEN 'Critical'
               ELSE 'Info'
           END AS severity_level
    FROM vulnerabilities
    GROUP BY plugin_name, severity
    ORDER BY severity DESC;
    """)
    conn.commit()
    conn.close()

def parse_nessus(nessus_file, db_path):
    """Parses the .nessus file and populates the database."""
    try:
        tree = ET.parse(nessus_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"XML Parsing Error: {e}")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    host_ids = {}
    
    # Insert hosts
    for report in root.findall(".//Report"):
        for host in report.findall(".//ReportHost"):
            host_data = {
                "ip": host.attrib.get("name"),
                "fqdn": None,
                "os": None,
                "credentialed_scan": None,
                "start_time": None,
                "end_time": None,
            }
            
            for tag in host.findall(".//tag"):
                tag_name = tag.attrib.get("name", "").lower()
                if tag_name == "host-ip":
                    host_data["ip"] = tag.text
                elif tag_name == "host-fqdn":
                    host_data["fqdn"] = tag.text
                elif tag_name == "operating-system":
                    host_data["os"] = tag.text
                elif tag_name == "credentialed_scan":
                    host_data["credentialed_scan"] = tag.text
                elif tag_name == "host_start":
                    host_data["start_time"] = tag.text
                elif tag_name == "host_end":
                    host_data["end_time"] = tag.text
            
            cursor.execute("""
                INSERT INTO hosts (ip, fqdn, os, credentialed_scan, start_time, end_time)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO NOTHING
            """, (host_data["ip"], host_data["fqdn"], host_data["os"], host_data["credentialed_scan"],
                  host_data["start_time"], host_data["end_time"]))
            
            cursor.execute("SELECT id FROM hosts WHERE ip = ?", (host_data["ip"],))
            host_id = cursor.fetchone()
            if host_id:
                host_ids[host.attrib.get("name")] = host_id[0]
    
    conn.commit()
    conn.close()

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return "No file uploaded", 400
    file = request.files["file"]
    db_path = os.path.join("/app/data", f"{file.filename}.db")
    file.save(file.filename)
    create_database(db_path)
    parse_nessus(file.filename, db_path)
    return jsonify({"message": "Database created successfully", "db": db_path})

@app.route("/query", methods=["POST"])
def run_query():
    data = request.json
    db_path = os.path.join("/app/data", data.get("db"))
    query = data.get("query")

    if not os.path.exists(db_path):
        return jsonify({"error": f"Database {db_path} not found"}), 400

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(query)

    # Fetch column names and row data
    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()

    conn.close()

    return jsonify({"columns": columns, "rows": rows})

@app.route("/databases", methods=["GET"])
def list_databases():
    db_files = [f for f in os.listdir("/app/data") if f.endswith(".db")]
    return jsonify(db_files)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
