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

def get_statistics(db_path):
    """Fetches scan statistics."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM hosts;")
    total_hosts = cursor.fetchone()[0]
    
    cursor.execute("""
        SELECT severity, COUNT(*) FROM vulnerabilities
        GROUP BY severity ORDER BY severity DESC;
    """)
    severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
    
    cursor.execute("SELECT port, COUNT(*) AS count FROM open_ports GROUP BY port ORDER BY count DESC LIMIT 10;")
    top_ports = cursor.fetchall()
    
    cursor.execute("SELECT ip FROM hosts LIMIT 1;")
    scan_name = cursor.fetchone()[0] if total_hosts > 0 else "Unknown Scan"
    
    conn.close()
    
    return {
        "scan_name": scan_name,
        "total_hosts": total_hosts,
        "severity_counts": severity_counts,
        "top_ports": top_ports
    }

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
    
    for report in root.findall(".//Report"):
        for host in report.findall(".//ReportHost"):
            host_name = host.attrib.get("name")
            cursor.execute("INSERT OR IGNORE INTO hosts (ip) VALUES (?)", (host_name,))
            cursor.execute("SELECT id FROM hosts WHERE ip = ?", (host_name,))
            host_id = cursor.fetchone()
            if host_id:
                host_ids[host_name] = host_id[0]
    
    for report in root.findall(".//Report"):
        for host in report.findall(".//ReportHost"):
            host_name = host.attrib.get("name")
            host_id = host_ids.get(host_name)
            if not host_id:
                continue
            
            for item in host.findall(".//ReportItem"):
                plugin_id = int(item.attrib.get("pluginID", 0))
                plugin_name = item.attrib.get("pluginName", "Unknown")
                severity = int(item.attrib.get("severity", 0))
                description = item.findtext("description", "").strip()
                solution = item.findtext("solution", "").strip()
                
                cursor.execute("""
                    INSERT INTO vulnerabilities (host_id, plugin_id, plugin_name, severity, description, solution)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (host_id, plugin_id, plugin_name, severity, description, solution))
                
                port = int(item.attrib.get("port", 0))
                protocol = item.attrib.get("protocol", "unknown")
                service = item.attrib.get("svc_name", "unknown")
                state = item.findtext("plugin_output", "").strip()
                
                cursor.execute("""
                    INSERT INTO open_ports (host_id, port, protocol, service, state)
                    VALUES (?, ?, ?, ?, ?)
                """, (host_id, port, protocol, service, state))
    
    conn.commit()
    conn.close()

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    db_path = os.path.join("/app/data", f"{file.filename}.db")
    file_path = os.path.join("/app/data", file.filename)

    try:
        file.save(file_path)
        create_database(db_path)
        parse_nessus(file_path, db_path)
        return jsonify({"message": "Database created successfully", "db": db_path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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

    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()

    conn.close()

    return jsonify({"columns": columns, "rows": rows})

@app.route("/statistics", methods=["POST"])
def fetch_statistics():
    data = request.json
    db_path = os.path.join("/app/data", data.get("db"))
    if not os.path.exists(db_path):
        return jsonify({"error": "Database not found"}), 400
    return jsonify(get_statistics(db_path))

@app.route("/databases", methods=["GET"])
def list_databases():
    db_files = [f for f in os.listdir("/app/data") if f.endswith(".db")]
    return jsonify(db_files)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
