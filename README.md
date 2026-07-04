# Automated System Log Parser (Python & Linux)

A lightweight, high-efficiency cybersecurity automation tool designed to scan Linux security infrastructure logs, detect brute-force login attempts, and compile an instant security metrics dashboard.

## 🛠️ Tech Stack & Concepts Used
* **Language:** Python 3
* **OS Environment:** Linux (Ubuntu/Kali) via CLI
* **Core Concepts:** File I/O Streams, Memory-Efficient Parsing, Sets (for unique filtering), Dictionaries (for frequency tracking).

## 🚀 How It Works
The script target-scans log structures (like `/var/log/auth.log`) searching for the `Failed password` flags. It isolates the timestamp, target account username, and source IP address of the attacker.

## 💻 Installation & Execution
Run the script locally inside your terminal:
```bash
python3 parser.py
