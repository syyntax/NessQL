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
        synopsis TEXT,
        see_also TEXT,
        plugin_output TEXT,
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
        SELECT severity, COUNT(DISTINCT(plugin_name)) FROM vulnerabilities
        GROUP BY severity ORDER BY severity DESC;
    """)
    severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
    
    cursor.execute("SELECT port, protocol, COUNT(DISTINCT(host_id)) AS count FROM open_ports WHERE NOT port = 0 GROUP BY port ORDER BY count DESC LIMIT 10;")
    top_ports = cursor.fetchall()
    
    cursor.execute("PRAGMA database_list;")
    scan_name = cursor.fetchone()[2] if total_hosts > 0 else "Unknown Scan"
    
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
                ON CONFLICT(ip) DO UPDATE SET fqdn=excluded.fqdn, os=excluded.os, 
                credentialed_scan=excluded.credentialed_scan, start_time=excluded.start_time, 
                end_time=excluded.end_time;
            """, (host_data["ip"], host_data["fqdn"], host_data["os"], host_data["credentialed_scan"],
                  host_data["start_time"], host_data["end_time"]))
            
            cursor.execute("SELECT id FROM hosts WHERE ip = ?", (host_data["ip"],))
            host_id = cursor.fetchone()
            if host_id:
                host_ids[host.attrib.get("name")] = host_id[0]
    
    # Insert vulnerabilities and open ports
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
                synopsis = item.findtext("synopsis", "").strip()
                see_also = item.findtext("see_also", "").strip()
                plugin_output = item.findtext("plugin_output", "").strip()
                
                cursor.execute("""
                    INSERT INTO vulnerabilities (host_id, plugin_id, plugin_name, severity, description, solution, synopsis, see_also, plugin_output)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (host_id, plugin_id, plugin_name, severity, description, solution, synopsis, see_also, plugin_output))
                
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

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(query)

        # Fetch column names
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        rows = cursor.fetchall()
        conn.close()

        return jsonify({"columns": columns, "rows": rows})
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500

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

@app.route("/query_plugin", methods=["POST"])
def query_plugin():
    """Queries the database for hosts affected by a specific plugin_name."""
    data = request.json
    db_path = os.path.join("/app/data", data.get("db"))
    plugin_name = data.get("plugin_name")

    if not os.path.exists(db_path):
        return jsonify({"error": f"Database {db_path} not found"}), 400

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT vulnerabilities.plugin_id, vulnerabilities.plugin_name, severity, hosts.ip, description, solution
            FROM vulnerabilities
            INNER JOIN hosts ON vulnerabilities.host_id = hosts.id
            WHERE plugin_name LIKE ?
            GROUP BY hosts.ip
            ORDER BY severity;
        """, (f"%{plugin_name}%",))

        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        conn.close()

        return jsonify({"columns": columns, "rows": rows})
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
