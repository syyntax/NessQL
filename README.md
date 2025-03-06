# NessQL

## Overview
NessQL is a web-based tool designed to process, analyze, and interact with security scan data from **.nessus** files. It provides an intuitive interface for security professionals to query, visualize, and modify vulnerability data efficiently. NessQL is built using **Flask**, **SQLite**, and **JavaScript**, making it lightweight and easy to deploy.

## Problem It Solves
Security assessments often generate large amounts of scan data, making it difficult to **query, analyze, and manage** vulnerabilities efficiently. **Traditional methods**, such as manually reviewing `.nessus` XML files or reports, or importing data into third-party tools, can be time-consuming and inefficient.

NessQL addresses this by:
- **Automating database creation** from `.nessus` files.
- **Providing a web-based SQL interface** to query vulnerabilities, hosts, and open ports.
- **Allowing users to modify severity levels** of vulnerabilities dynamically.
- **Displaying affected hosts for each vulnerability** in an easy-to-use modal window.
- **Enabling predefined queries** for quick analysis through the left-pane navigation.

Ultimately, this tool will also serve as a guide for how to manually validate Nessus findings and test the exploitability of discovered vulnerabilities.

By using NessQL, security analysts can quickly **identify critical vulnerabilities, explore affected systems, and efficiently manage security data** from Nessus scans.

## Installation
NessQL is built using Docker for portability.

### Clone the Repo
```bash
git clone https://github.com/syyntax/NessQL.git
```

### Run the Container
Run the container using `docker-compose`:
```bash
cd NessQL
docker-compose up -d
```

### Access the Web UI
In a browser, navigate to http://localhost:5000.

![NessQL Web UI](https://cyberhacktics.sfo2.digitaloceanspaces.com/screenshot01.png)