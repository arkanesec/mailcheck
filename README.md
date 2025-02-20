## MailCheck: Email Security Analysis & Threat Detection


![image](https://github.com/user-attachments/assets/12e7f538-0603-422b-96e5-151e7232d351)

This script, `mailcheck.py`, provides a comprehensive analysis of email files to identify potential security threats. It dissects various email components, including headers, body content, URLs, and attachments, to detect suspicious patterns and flag potential malicious activities.

### Features

* **Header Analysis:**  
    * Extracts all email headers.
    * Identifies mismatches between the "Return-Path" and "From" addresses, which can indicate spoofing attempts.

    ```python
    def analyze_headers(email_message, results):
        headers = results["headers"]
        if "Return-Path" in headers and "From" in headers:
            return_path = headers["Return-Path"].strip("<>")
            from_address = re.findall(r'<(.+?)>', headers["From"])
            if from_address and return_path!= from_address:
                results["suspicious_headers"] = {
                    "type": "mismatch",
                    "return_path": return_path,
                    "from": from_address
                }
    ```

* **Body Content Analysis:** 
    * Extracts text content from both plain text and HTML emails.
    * Parses HTML content using BeautifulSoup to identify and extract URLs embedded in `<a>`, `<img>`, `<script>`, and `<iframe>` tags.

    ```python
    def analyze_body(email_message, results):
        if email_message.is_multipart():
            for part in email_message.walk():
                process_message_part(part, results)
        else:
            process_message_part(email_message, results)

    def extract_urls_from_html(html_content, results):
        soup = BeautifulSoup(html_content, "html.parser")
        urls =
        for tag in soup.find_all(['a', 'img', 'script', 'iframe']):
            url = tag.get('href') or tag.get('src')
            if url and validate_url(url):
                urls.append(url)
        results["urls"].extend(list(set(urls)))
    ```

* **URL Analysis:** 
    * Validates URL format to ensure they are well-formed.
    * Performs DNS lookups to resolve the IP addresses associated with the extracted URLs.
    * Leverages VirusTotal and urlscan.io APIs to check URLs against known threat intelligence databases (requires API keys).

    ```python
    def analyze_url(url):
        result = {"url": url, "status": "analyzed"}
        #... (validation and DNS lookup)...

        if VIRUSTOTAL_API_KEY:
            vt_result = check_virustotal(url)
            if vt_result:
                result["virustotal"] = vt_result

        if URLSCAN_IO_API_KEY:
            urlscan_result = check_urlscan(url)
            if urlscan_result:
                result["urlscan"] = urlscan_result

        return result
    ```

* **Attachment Analysis:** 
    * Extracts attachments from the email.
    * Calculates SHA256 hashes for each attachment to facilitate identification and comparison with known malware samples.
    * Submits attachments to the VirusTotal API for analysis (requires API key).

    ```python
    def analyze_file(filename, content):
        result = {
            "filename": filename,
            "sha256": hashlib.sha256(content).hexdigest(),
            "status": "analyzed"
        }

        if VIRUSTOTAL_API_KEY:
            try:
                files = {'file': (filename, content)}
                headers = {'x-apikey': VIRUSTOTAL_API_KEY}
                response = requests.post('https://www.virustotal.com/api/v3/files', files=files, headers=headers, timeout=TIMEOUT)
                result["virustotal"] = response.json()
            except requests.exceptions.RequestException as e:
                logger.warning(f"VirusTotal API error for file {filename}: {str(e)}")

        return result
    ```

* **Reporting:**
    * **Findings Report (`findings_report.txt`):** Provides a human-readable summary of the analysis, including header information, suspicious headers, and attachment details.
    * **Extracted Items:** Saves extracted URLs, domains, IP addresses, and email addresses to separate text files (`urls.txt`, `domains.txt`, `ip_addresses.txt`, `email_addresses.txt`) for further investigation or use in other security tools.
    * **Summary Report (`extracted_items_summary.txt`):**  Presents a consolidated overview of all extracted items with summary counts.
    * **Full Analysis (`full_analysis.json`):** Stores the complete analysis results in JSON format for detailed review or programmatic access.


### Requirements

* Python 3.6 or higher
* Required modules: `email`, `dnspython`, `requests`, `beautifulsoup4`
* Optional: VirusTotal API key, urlscan.io API key

### Installation

1. Clone the repository or download `mailcheck.py`.
2. Install the required modules: `pip install -r requirements.txt`
3. Set the environment variables `VIRUSTOTAL_API_KEY` and `URLSCAN_IO_API_KEY` if you have API keys.

### Usage

1. Run the script: `python mailcheck.py`
2. Enter the path to the email file you want to analyze.

### Output

The analysis results will be saved in a new directory within the `analysis_results` folder. The directory name includes the email filename and a timestamp.

### Disclaimer

This script is intended for informational and educational purposes only. Use it responsibly and at your own risk. The developers are not responsible for any misuse or damage caused by this script.

