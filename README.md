# Log File Analyzer

## Overview

The **Log File Analyzer** is a Python script that processes server log files to extract and analyze key information such as:
- **Requests per IP address**: Counts how many requests were made from each IP.
- **Most accessed endpoints**: Identifies frequently accessed resources (e.g., `/home`, `/login`).
- **Suspicious activity**: Detects failed login attempts and the IP addresses responsible.

The results are displayed in the console and saved in a structured CSV file for further analysis.

---

## Features

1. **Count Requests per IP**:
   - Tallies the number of requests made by each IP address.

2. **Identify the Most Frequently Accessed Endpoint**:
   - Extracts the endpoints (e.g., `/login`, `/home`) and ranks them by access frequency.

3. **Detect Suspicious Activity**:
   - Tracks failed login attempts, associating them with the IP addresses that triggered them.

4. **Save Results to CSV**:
   - Outputs analysis results to a CSV file named `log_analysis_results.csv` with the following sections:
     - **Requests per IP**: Columns: `IP Address`, `Request Count`
     - **Most Accessed Endpoint**: Columns: `Endpoint`, `Access Count`
     - **Suspicious Activity**: Columns: `IP Address`, `Failed Login Count`

---

## Prerequisites

Ensure you have the following installed:
- Python 3.x
- Required libraries: `csv` and `re` (standard libraries)

---

## Usage

1. Clone or download this repository.
2. Place your log file in the same directory as the script and rename it to `server_logs.txt` (or adjust the file path in the script).
3. Run the script:
   ```bash
   python loganalyzer.py
