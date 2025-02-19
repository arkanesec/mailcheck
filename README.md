# mailcheck
MailCheck: Email Security Analysis & Threat Detection Tool
MailCheck is a Python-based tool designed to analyze email files for potential security threats. It performs various checks on email headers, body content, URLs, and attachments to identify suspicious patterns and indicators of compromise.

Features
Header Analysis:
Checks for inconsistencies between "Return-Path" and "From" addresses.
Identifies potentially spoofed or forged headers.
Body Content Analysis:
Extracts and analyzes both plain text and HTML content.
Detects potentially malicious URLs embedded in the email body.
URL Analysis:
Performs DNS lookups to identify suspicious domains.
Integrates with VirusTotal and urlscan.io APIs for reputation checks and detailed analysis (requires API keys).
Attachment Analysis:
Calculates SHA256 hashes of attachments for identification and comparison.
Scans files with VirusTotal API for malware detection (requires API key).
Logging:
Provides detailed logging of analysis steps and findings.
Output:
Generates a JSON report summarizing the analysis results.
Requirements
Python 3.7 or higher
Required Python packages:
dnspython
requests
beautifulsoup4
Installation
Clone the repository or download the script.
Install the required packages:
Bash

pip install -r requirements.txt

Set up API keys (optional but recommended):
Create environment variables VIRUSTOTAL_API_KEY and URLSCAN_IO_API_KEY with your respective API keys.
Usage
Run the script:
Bash

python mailcheck.py
Enter the path to the email file you want to analyze.
The script will generate a JSON file with the analysis results.

Example

![image](https://github.com/user-attachments/assets/12e7f538-0603-422b-96e5-151e7232d351)

python mailcheck.py

Enter email file path: /path/to/suspicious_email.eml

Analysis Results saved to: analysis_results_suspicious_email.eml.json


This tool is intended for security analysis and research purposes.
Use it responsibly and ethically.
The accuracy of the analysis depends on the quality of the data sources and API services used.
Always exercise caution when handling potentially malicious emails and files.
The author is not responsible for any misuse or damage caused by this tool.
Contributing
Contributions are welcome! Feel free to submit bug reports, feature requests, or pull requests.
