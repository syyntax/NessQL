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
    db_name = data.get("db")  # Ensure we only get the database name, not the full path
    db_path = os.path.join("/app/data", db_name)  # Ensure correct path
    query = data.get("query")

    if not os.path.exists(db_path):
        return jsonify({"error": f"Database {db_name} not found"}), 400

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute(query)
        results = cursor.fetchall()
    except sqlite3.Error as e:
        results = {"error": str(e)}

    conn.close()
    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
