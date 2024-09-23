# Domintel - Domain Information Tool

This Python script provides a GUI tool to gather WHOIS, DNS, and SSL/TLS information for a given domain.

### Requirements
- Python 3.x
- `whois` library (`pip install python-whois`)
- `dnspython` library (`pip install dnspython`)
- `cryptography` library (`pip install cryptography`)
- `tkinter` (usually included in Python installations)
- `reportlab` library (`pip install reportlab`)

### Features
- **WHOIS Lookup**: Retrieves WHOIS information for the domain.
- **DNS Records**: Fetches various DNS records (A, AAAA, MX, TXT, CNAME).
- **SSL/TLS Information**: Provides details about the SSL/TLS certificate, including issuer, subject, validity, and more.
- **Generate PDF Report**: Creates a detailed PDF report summarizing the gathered information.

### Usage
1. Enter a domain name in the GUI.
2. Click "Scan Domain" to initiate the scan.
3. View the results in the text area.
4. Optionally, click "Download PDF Report" to save a PDF report of the domain information.

### How to Run
1. Ensure all required libraries are installed.
2. Run the script (`python your_script.py`).
3. The GUI window will appear, allowing you to interact with the tool.

### Example
```python
python domain_intel.py
```

## Troubleshooting

If you encounter any issues, ensure:
- Your internet connection is active.
- You have permissions to access WHOIS and DNS information for the domain.
