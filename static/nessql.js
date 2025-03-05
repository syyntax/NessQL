document.addEventListener("DOMContentLoaded", loadDatabases);

function uploadFile() {
    const fileInput = document.getElementById("file-input");
    const fileError = document.getElementById("file-error");
    const file = fileInput.files[0];
    const progressBar = document.getElementById("progress-bar");
    const uploadStatus = document.getElementById("upload-status");

    if (!file || !file.name.endsWith(".nessus")) {
        fileError.style.display = "block";
        return;
    }
    fileError.style.display = "none";

    const formData = new FormData();
    formData.append("file", file);

    progressBar.style.width = "0%";  // Reset progress bar
    uploadStatus.textContent = "Uploading...";

    fetch("/upload", {
        method: "POST",
        body: formData
    })
    .then(response => {
        progressBar.style.width = "50%"; // Midway progress
        return response.json();
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            uploadStatus.textContent = "Upload Failed!";
            progressBar.style.width = "0%"; // Reset on error
            alert("Error: " + data.error);
        } else {
            progressBar.style.width = "100%"; // Complete
            uploadStatus.textContent = "Database Created Successfully!";
            loadDatabases(); // Refresh database list
        }
    })
    .catch(error => {
        uploadStatus.textContent = "Upload Failed!";
        progressBar.style.width = "0%"; // Reset on error
        alert("Upload failed: " + error);
    });
}

function loadDatabases() {
    fetch("/databases")
    .then(response => response.json())
    .then(databases => {
        const selector = document.getElementById("database-selector");
        selector.innerHTML = "";
        databases.forEach(db => {
            const option = document.createElement("option");
            option.value = db;
            option.textContent = db;
            selector.appendChild(option);
        });
        if (databases.length > 0) {
            fetchStatistics(databases[0]);
        }
    });
}

function executeQuery() {
    const db = document.getElementById("database-selector").value;
    const query = document.getElementById("sql-query").value;

    if (!db) {
        alert("Please select a database.");
        return;
    }

    fetch("/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ db: db, query: query })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert("Error: " + data.error);
        } else {
            displayResults(data.columns, data.rows);
        }
    })
    .catch(error => {
        alert("Query failed: " + error);
    });
}

function fetchPluginDetails(pluginName) {
    const db = document.getElementById("database-selector").value;

    fetch("/query_plugin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ db: db, plugin_name: pluginName })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert("Error: " + data.error);
        } else {
            showModal(data.rows[0]);
        }
    })
    .catch(error => {
        alert("Query failed: " + error);
    });
}

function displayResults(columns, rows) {
    const tableHeader = document.getElementById("query-results-header");
    const tableBody = document.getElementById("query-results-body");
    const resultCount = document.getElementById("query-result-count");

    tableHeader.innerHTML = "";
    tableBody.innerHTML = "";

    // Update the query result count
    resultCount.innerHTML = `<strong>Records Found:</strong> ${rows.length}`;

    if (columns.length > 0) {
        const headerRow = document.createElement("tr");
        columns.forEach(header => {
            const th = document.createElement("th");
            th.textContent = header.replace(/_/g, " ").toUpperCase();
            headerRow.appendChild(th);
        });
        tableHeader.appendChild(headerRow);

        rows.forEach(row => {
            const tr = document.createElement("tr");
            row.forEach((cell, index) => {
                const td = document.createElement("td");

                // If the column is "plugin_name", make it clickable
                if (columns[index] === "plugin_name") {
                    const link = document.createElement("a");
                    link.href = "#";
                    link.textContent = cell;
                    link.onclick = () => fetchPluginDetails(cell);
                    td.appendChild(link);
                } else {
                    td.textContent = cell;
                }
                tr.appendChild(td);
            });
            tableBody.appendChild(tr);
        });
    } else {
        tableBody.innerHTML = "<tr><td colspan='" + columns.length + "'>No results found</td></tr>";
    }
}

function showModal(data) {
    document.getElementById("plugin-title").textContent = data[1];  // plugin_name
    document.getElementById("plugin-id").textContent = data[0];  // plugin_id
    document.getElementById("plugin-severity").textContent = getSeverityLabel(data[2]);  // severity
    document.getElementById("plugin-description").textContent = data[4];  // description
    document.getElementById("plugin-synopsis").textContent = data[5];  // synopsis
    document.getElementById("plugin-see-also").textContent = data[6];  // see_also
    document.getElementById("plugin-output").textContent = data[7];  // plugin_output

    document.getElementById("plugin-modal").style.display = "block";
}

function fetchStatistics() {
    const db = document.getElementById("database-selector").value;
    fetch("/statistics", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ db })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById("scan-name").textContent = data.scan_name;
        document.getElementById("total-hosts").textContent = data.total_hosts;
        document.getElementById("critical-count").textContent = data.severity_counts[4] || 0;
        document.getElementById("high-count").textContent = data.severity_counts[3] || 0;
        document.getElementById("medium-count").textContent = data.severity_counts[2] || 0;
        document.getElementById("low-count").textContent = data.severity_counts[1] || 0;
        document.getElementById("info-count").textContent = data.severity_counts[0] || 0;
        
        const topPortsTable = document.getElementById("top-ports-table");
        topPortsTable.innerHTML = "";
        data.top_ports.forEach(row => {
            const tr = document.createElement("tr");
            row.forEach(cell => {
                const td = document.createElement("td");
                td.textContent = cell;
                tr.appendChild(td);
            });
            topPortsTable.appendChild(tr);
        });
    });
}

function fetchPluginDetails(pluginName) {
    const db = document.getElementById("database-selector").value;

    fetch("/query_plugin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ db: db, plugin_name: pluginName })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert("Error: " + data.error);
        } else if (data.rows.length > 0) {
            showModal(data.columns, data.rows); // Ensure modal is displayed
        } else {
            alert("No data found for this plugin.");
        }
    })
    .catch(error => {
        alert("Query failed: " + error);
    });
}

function showModal(columns, data) {
    const modal = document.getElementById("plugin-modal");
    const hostsTableBody = document.getElementById("affected-hosts");
    const severityDropdown = document.getElementById("plugin-severity");

    if (!modal || !hostsTableBody || !severityDropdown) {
        alert("Error: Modal elements not found.");
        return;
    }

    if (!data || data.length === 0) {
        alert("No data found.");
        return;
    }

    const pluginData = data[0];

    document.getElementById("plugin-title").textContent = pluginData[1];  // plugin_name
    document.getElementById("plugin-id").textContent = pluginData[0];  // plugin_id

    // Set the correct severity in the dropdown
    severityDropdown.innerHTML = `
        <option value="4">Critical</option>
        <option value="3">High</option>
        <option value="2">Medium</option>
        <option value="1">Low</option>
        <option value="0">Info</option>
        <option value="5">False Positive</option>
    `;
    severityDropdown.value = pluginData[2];  // Set current severity as selected

    document.getElementById("plugin-description").textContent = pluginData[4];  // description
    document.getElementById("plugin-synopsis").textContent = pluginData[6];  // synopsis
    document.getElementById("plugin-see-also").textContent = pluginData[7];  // see_also
    document.getElementById("plugin-output").textContent = pluginData[8];  // plugin_output

    // Populate affected hosts table
    hostsTableBody.innerHTML = ""; // Clear existing data

    data.forEach(row => {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.textContent = row[3]; // IP Address
        tr.appendChild(td);
        hostsTableBody.appendChild(tr);
    });

    modal.style.display = "block"; // Show the modal
}

function closeModal() {
    document.getElementById("plugin-modal").style.display = "none";
}

function getSeverityLabel(severity) {
    const labels = ["Info", "Low", "Medium", "High", "Critical"];
    return labels[severity] || "Unknown";
}

function saveSeverityChange() {
    const db = document.getElementById("database-selector").value;
    const pluginId = document.getElementById("plugin-id").textContent;
    const newSeverity = document.getElementById("plugin-severity").value;

    fetch("/update_severity", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ db: db, plugin_id: pluginId, severity: newSeverity })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert("Error: " + data.error);
        } else {
            alert("Severity updated successfully.");
            closeModal(); // Close the modal after updating
            executeQuery(); // Refresh the results table
        }
    })
    .catch(error => {
        alert("Update failed: " + error);
    });
}

function setQuery(query) {
    document.getElementById("sql-query").value = query;
    // executeQuery(); // Automatically runs the query
}