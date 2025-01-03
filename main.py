import argparse
import requests
import logging
from requests.exceptions import RequestException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the command-line argument parser.
    
    Returns:
        argparse.ArgumentParser: Argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="vuln-Security-Header-Analyzer: Analyzes HTTP response headers for security vulnerabilities."
    )
    parser.add_argument(
        "url",
        help="The URL of the web application to analyze for security vulnerabilities."
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging."
    )
    parser.add_argument(
        "--version",
        action="version",
        version="vuln-Security-Header-Analyzer 1.0"
    )
    return parser

def analyze_headers(headers):
    """
    Analyzes HTTP response headers for potential security vulnerabilities.
    
    Args:
        headers (dict): HTTP response headers.
    
    Returns:
        dict: Analysis report of vulnerabilities found.
    """
    vulnerabilities = []
    recommendations = {
        "Strict-Transport-Security": "Missing. This header enforces secure (HTTPS) connections.",
        "Content-Security-Policy": "Missing. This helps prevent XSS attacks by restricting resource loading.",
        "X-Content-Type-Options": "Missing. This prevents MIME type sniffing.",
        "X-Frame-Options": "Missing. This helps prevent clickjacking attacks.",
        "Referrer-Policy": "Missing. This controls the information sent with the Referer header.",
        "Permissions-Policy": "Missing. This restricts the use of browser features like camera and microphone."
    }
    
    for header, message in recommendations.items():
        if header not in headers:
            vulnerabilities.append({"header": header, "issue": message})
    
    return vulnerabilities

def main():
    """
    Main function to perform the security header analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url
    logging.info(f"Starting analysis for URL: {url}")

    try:
        response = requests.get(url)
        response.raise_for_status()
        logging.info(f"Received response with status code: {response.status_code}")
    except RequestException as e:
        logging.error(f"Error making request to {url}: {e}")
        return

    headers = response.headers
    logging.debug(f"Response headers: {headers}")

    vulnerabilities = analyze_headers(headers)

    if vulnerabilities:
        logging.info("Security vulnerabilities detected:")
        for vuln in vulnerabilities:
            logging.info(f"- {vuln['header']}: {vuln['issue']}")
    else:
        logging.info("No security vulnerabilities detected in the headers.")

if __name__ == "__main__":
    main()