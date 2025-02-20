try:
    import email
    import email.policy
    import hashlib
    import re
    import dns.resolver
    import requests
    from bs4 import BeautifulSoup
    from typing import Dict, Any, List, Optional
    from concurrent.futures import ThreadPoolExecutor
    import logging
    import os
    import json
    import base64
    from urllib.parse import urlparse
except ImportError as e:
    print(f"""
Error: Missing required modules. Please install them using:
pip install -r requirements.txt

Missing module: {str(e)}
    """)
    exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
URLSCAN_IO_API_KEY = os.getenv('URLSCAN_IO_API_KEY', '')
MAX_WORKERS = 5
TIMEOUT = 30
MAX_FILE_SIZE = 32 * 1024 * 1024  # 32MB max file size
SUPPORTED_CONTENT_TYPES = {'text/plain', 'text/html', 'message/rfc822'}

def print_ascii_art():
    art = """
    ███╗   ███╗ █████╗ ██╗██╗      ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
    ████╗ ████║██╔══██╗██║██║     ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
    ██╔████╔██║███████║██║██║     ██║     ███████║█████╗  ██║     █████╔╝ 
    ██║╚██╔╝██║██╔══██║██║██║     ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
    ██║ ╚═╝ ██║██║  ██║██║███████╗╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
                                                                            
                    Email Security Analysis & Threat Detection
                          [ Version 1.0 | @4rk4n3 ]
    """
    print(art)

def validate_url(url: str) -> bool:
    """Validate URL format and scheme."""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe handling."""
    return re.sub(r'[^a-zA-Z0-9._-]', '_', filename)

def analyze_email(email_message: email.message.EmailMessage) -> Dict[str, Any]:
    """
    Analyzes an email for potentially malicious content.
    
    Args:
        email_message: Parsed email message object
    Returns:
        Dict containing analysis results
    """
    try:
        results = {
            "headers": dict(email_message.items()),
            "attachments": [],
            "urls": [],
            "body_text": "",
            "analysis_status": "success"
        }

        # Header analysis
        analyze_headers(email_message, results)
        
        # Body analysis
        analyze_body(email_message, results)
        
        # Parallel processing for URLs and attachments
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            if results.get("urls"):
                url_futures = [executor.submit(analyze_url, url) for url in set(results["urls"])]
                results["url_analysis"] = [future.result() for future in url_futures if future.result()]

            if results.get("attachments"):
                attachment_futures = [executor.submit(analyze_file, att["filename"], att["content"]) 
                                   for att in results["attachments"]]
                results["file_analysis"] = [future.result() for future in attachment_futures if future.result()]

        return results

    except Exception as e:
        logger.error(f"Error in analyze_email: {str(e)}")
        return {"analysis_status": "error", "error_message": str(e)}

def analyze_headers(email_message: email.message.EmailMessage, results: Dict[str, Any]) -> None:
    """Analyzes email headers for suspicious patterns."""
    try:
        headers = results["headers"]
        if "Return-Path" in headers and "From" in headers:
            return_path = headers["Return-Path"].strip("<>")
            from_address = re.findall(r'<(.+?)>', headers["From"])
            if from_address and return_path != from_address[0]:
                results["suspicious_headers"] = {
                    "type": "mismatch",
                    "return_path": return_path,
                    "from": from_address[0]
                }
    except Exception as e:
        logger.warning(f"Header analysis error: {str(e)}")

def analyze_body(email_message: email.message.EmailMessage, results: Dict[str, Any]) -> None:
    """Extracts and analyzes email body content."""
    try:
        if email_message.is_multipart():
            for part in email_message.walk():
                process_message_part(part, results)
        else:
            process_message_part(email_message, results)
    except Exception as e:
        logger.warning(f"Body analysis error: {str(e)}")

def process_message_part(part: email.message.EmailMessage, results: Dict[str, Any]) -> None:
    """Processes individual email parts."""
    try:
        content_type = part.get_content_type()
        
        if content_type in ["text/plain", "text/html"]:
            content = part.get_payload(decode=True)
            charset = part.get_charset() or 'utf-8'
            decoded_content = content.decode(charset, errors='replace')
            
            results["body_text"] += decoded_content
            
            if content_type == "text/html":
                extract_urls_from_html(decoded_content, results)
                
        elif part.get_content_disposition() == "attachment":
            handle_attachment(part, results)
            
    except Exception as e:
        logger.warning(f"Part processing error: {str(e)}")

def extract_urls_from_html(html_content: str, results: Dict[str, Any]) -> None:
    """Extracts and validates URLs from HTML content."""
    try:
        soup = BeautifulSoup(html_content, "html.parser", features="html.parser")
        urls = []
        for tag in soup.find_all(['a', 'img', 'script', 'iframe']):
            url = tag.get('href') or tag.get('src')
            if url and validate_url(url):
                urls.append(url)
        results["urls"].extend(list(set(urls)))
    except Exception as e:
        logger.warning(f"URL extraction error: {str(e)}")

def handle_attachment(part: email.message.EmailMessage, results: Dict[str, Any]) -> None:
    """Processes email attachments safely."""
    try:
        filename = sanitize_filename(part.get_filename() or 'unnamed_attachment')
        content = part.get_payload(decode=True)
        
        if len(content) > MAX_FILE_SIZE:
            logger.warning(f"Attachment {filename} exceeds size limit")
            return

        file_hash = hashlib.sha256(content).hexdigest()
        results["attachments"].append({
            "filename": filename,
            "sha256": file_hash,
            "size": len(content),
            "content": content,
            "content_type": part.get_content_type()
        })
    except Exception as e:
        logger.warning(f"Attachment handling error: {str(e)}")

def analyze_url(url: str) -> Dict[str, Any]:
    """Analyzes a URL for potential threats."""
    try:
        result = {"url": url, "status": "analyzed"}
        
        # Basic validation
        if not re.match(r'https?://', url):
            return {"url": url, "status": "invalid"}

        # DNS lookup
        domain = re.search(r"(?:https?://)?(?:www\.)?([^/]+)", url).group(1)
        try:
            ip_address = str(dns.resolver.resolve(domain)[0])
            result["ip_address"] = ip_address
        except dns.resolver.NXDOMAIN:
            result["status"] = "domain_not_found"
            return result

        # API checks
        if VIRUSTOTAL_API_KEY:
            vt_result = check_virustotal(url)
            if vt_result:
                result["virustotal"] = vt_result

        if URLSCAN_IO_API_KEY:
            urlscan_result = check_urlscan(url)
            if urlscan_result:
                result["urlscan"] = urlscan_result

        return result

    except Exception as e:
        logger.error(f"URL analysis error for {url}: {str(e)}")
        return {"url": url, "status": "error", "error": str(e)}

def analyze_file(filename: str, content: bytes) -> Dict[str, Any]:
    """
    Analyzes a file for potential threats.
    
    Args:
        filename: Name of the file
        content: Binary content of the file
    Returns:
        Dict containing analysis results
    """
    try:
        result = {
            "filename": filename,
            "sha256": hashlib.sha256(content).hexdigest(),
            "status": "analyzed"
        }

        if VIRUSTOTAL_API_KEY:
            try:
                files = {'file': (filename, content)}
                headers = {'x-apikey': VIRUSTOTAL_API_KEY}
                response = requests.post(
                    'https://www.virustotal.com/api/v3/files',
                    files=files,
                    headers=headers,
                    timeout=TIMEOUT
                )
                result["virustotal"] = response.json()
            except requests.exceptions.RequestException as e:
                logger.warning(f"VirusTotal API error for file {filename}: {str(e)}")

        return result

    except Exception as e:
        logger.error(f"File analysis error for {filename}: {str(e)}")
        return {
            "filename": filename,
            "status": "error",
            "error": str(e)
        }

def check_virustotal(url: str) -> Optional[Dict[str, Any]]:
    """Check URL against VirusTotal API with proper error handling."""
    if not VIRUSTOTAL_API_KEY:
        return None

    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        response = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers=headers,
            timeout=TIMEOUT
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.warning(f"VirusTotal API error: {str(e)}")
        return None

def check_urlscan(url: str) -> Dict[str, Any]:
    """Check URL against urlscan.io API."""
    try:
        headers = {
            'API-Key': URLSCAN_IO_API_KEY,
            'Content-Type': 'application/json'
        }
        data = {"url": url, "visibility": "public"}
        response = requests.post(
            'https://urlscan.io/api/v1/scan',
            headers=headers,
            json=data,
            timeout=TIMEOUT
        )
        return response.json()
    except Exception as e:
        logger.warning(f"urlscan.io API error: {str(e)}")
        return None

def main():
    """Main execution function with improved error handling."""
    print_ascii_art()
    
    try:
        email_path = input("\nEnter email file path: ").strip()
        
        if not os.path.exists(email_path):
            logger.error(f"Email file not found: {email_path}")
            return

        if not os.path.isfile(email_path):
            logger.error(f"Path is not a file: {email_path}")
            return

        file_size = os.path.getsize(email_path)
        if file_size > MAX_FILE_SIZE:
            logger.error(f"File size ({file_size} bytes) exceeds maximum limit ({MAX_FILE_SIZE} bytes)")
            return

        logger.info(f"Analyzing email file: {email_path}")
        
        with open(email_path, "rb") as f:
            policy = email.policy.default.clone(cte_type=False)
            email_message = email.message_from_binary_file(f, policy=policy)

        logger.info("Starting email analysis...")
        results = analyze_email(email_message)
        
        output_file = f"analysis_results_{os.path.basename(email_path)}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        
        print(f"\nAnalysis Results saved to: {output_file}")
        logger.info("Analysis completed successfully")

    except PermissionError:
        logger.error(f"Permission denied accessing file: {email_path}")
    except json.JSONDecodeError:
        logger.error("Error formatting results as JSON")
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")

if __name__ == "__main__":
    main()
