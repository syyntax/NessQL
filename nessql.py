import argparse
import sqlite3
import xml.etree.ElementTree as ET
import os
from flask import Flask, request, render_template, jsonify

def create_database(db_path):
    """Creates the SQLite database with the required schema."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.executescript("""
    DROP TABLE IF EXISTS hosts;
    DROP TABLE IF EXISTS vulnerabilities;
    DROP TABLE IF EXISTS open_ports;
    DROP VIEW IF EXISTS view_ports;
    
    CREATE TABLE hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        fqdn TEXT,
        os TEXT,
        credentialed_scan TEXT,
        start_time TEXT,
        end_time TEXT
    );
    
    CREATE TABLE vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER,
        plugin_id INTEGER,
        plugin_name TEXT,
        severity INTEGER,
        description TEXT,
        solution TEXT,
        FOREIGN KEY (host_id) REFERENCES hosts(id)
    );
    
    CREATE TABLE open_ports (
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
    """)
    conn.commit()
    conn.close()

def parse_nessus(nessus_file, db_path):
    """Parses the .nessus file and populates the database."""
    tree = ET.parse(nessus_file)
    root = tree.getroot()
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
            host_id = cursor.fetchone()[0]
            host_ids[host.attrib.get("name")] = host_id
    
    # Insert vulnerabilities and open ports
    for report in root.findall(".//Report"):
        for host in report.findall(".//ReportHost"):
            host_name = host.attrib.get("name")
            host_id = host_ids.get(host_name)
            if not host_id:
                continue
            
            for item in host.findall(".//ReportItem"):
                plugin_id = item.attrib.get("pluginID")
                plugin_name = item.attrib.get("pluginName")
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

@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return "No file uploaded", 400
    file = request.files["file"]
    db_path = f"{file.filename}.db"
    file.save(file.filename)
    create_database(db_path)
    parse_nessus(file.filename, db_path)
    return jsonify({"message": "Database created successfully", "db": db_path})

@app.route("/query", methods=["POST"])
def run_query():
    data = request.json
    db_path = data.get("db")
    query = data.get("query")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
