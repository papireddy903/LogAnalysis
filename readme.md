# Log File Analyzer

The **Log File Analyzer** is a Python script that analyzes log files to extract useful information such as IP address request counts, most frequently accessed endpoints, and suspicious login activities. The script processes logs and generates a report to help identify potential issues such as multiple failed login attempts. It also exports the analysis results into a CSV file for easy sharing and viewing.

## Features
- **IP Address Request Counts**: Displays the count of requests made from each IP address.
- **Most Accessed Endpoint**: Identifies the most frequently accessed endpoint from the log data.
- **Suspicious Login Activity Detection**: Flags IP addresses with failed login attempts above a specified threshold.
- **CSV Export**: Saves the analysis results into a CSV file for easy sharing or further processing.

## Requirements
- Python 3.x
- `collections` module (included with Python)
- `re` module (included with Python)
- `csv` module (included with Python)
- `logging` module (included with Python)

## Installation

1. Clone this repository or download the script to your local machine.
2. Ensure you have Python 3.x installed.
3. There are no external dependencies, so no need for additional installations.

## Usage

1. Place your log file in the same directory as the script or provide the absolute path to the log file.
2. Run the script from the command line:

   ```bash
   python log_file_analyzer.py
    ```
3. Output should look like this:
```bash
--- IP Address Requests ---
IP Address                              Request Count
203.0.113.5                             8
198.51.100.23                           8
192.168.1.1                             7
10.0.0.2                                6
192.168.1.100                           5


--- Most Frequently Accessed Endpoint ---
/login (Accessed 13 times)

--- Suspicious Activity Detected ---
IP Address                              Failed Login Attempts
203.0.113.5                             8
```