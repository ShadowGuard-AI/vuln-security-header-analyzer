import argparse
import logging
import re
import sys

import requests
from requests.exceptions import RequestException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

REQUEST_TIMEOUT = 10

# Header values are never logged in clear. Credential shaped headers are
# always masked, and verbose mode logs names with masked values only.
SENSITIVE_HEADERS = {"set-cookie", "authorization", "proxy-authorization", "cookie"}


# The set above names the headers that must never print, but the masker
# below ignores the distinction and masks every value it is given. That is
# wider than the set requires, and I keep it that way: a header I did not
# think of cannot leak through a list I forgot to extend.
def masked_header_log(headers):
    lines = []
    for name in headers:
        lines.append(f"{name}: *** (value masked)")
    return "; ".join(lines)


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
        "--user-agent",
        default=None,
        help="Custom User-Agent header to send with the request."
    )
    parser.add_argument(
        "--max-redirects",
        type=int,
        default=30,
        help="Maximum number of redirects to follow (default: 30)."
    )
    parser.add_argument(
        "--output-file",
        default=None,
        help="Write the analysis report to this file as well as logging it."
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
    Checks presence, and the values of the headers whose security posture
    is defined by their value.

    Args:
        headers (dict): HTTP response headers.

    Returns:
        list: Findings, each a dict with the header name and the issue.
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

    # Presence is tested against the response header mapping, which for a
    # requests response ignores case. A header sent as x-frame-options in
    # lower case counts as present here, as it should.
    for header, message in recommendations.items():
        if header not in headers:
            vulnerabilities.append({"header": header, "issue": message})

    # Value checks for the headers present.
    xfo = headers.get("X-Frame-Options")
    if xfo is not None and xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
        vulnerabilities.append({"header": "X-Frame-Options",
                                "issue": "Present, but its value is neither DENY nor SAMEORIGIN, so framing is not reliably prevented."})

    csp = headers.get("Content-Security-Policy")
    if csp is not None:
        lowered = csp.lower()
        tokens = re.split(r"[\s;]+", lowered)
        # The elif means a policy with both problems reports only the
        # unsafe one. The wildcard finding is not hidden on purpose, it is
        # queued behind the worse problem in the same header.
        if "'unsafe-inline'" in lowered or "'unsafe-eval'" in lowered:
            vulnerabilities.append({"header": "Content-Security-Policy",
                                    "issue": "Present, but it allows unsafe-inline or unsafe-eval, which weakens its XSS protection."})
        elif "*" in tokens:
            vulnerabilities.append({"header": "Content-Security-Policy",
                                    "issue": "Present, but it uses a wildcard source, which allows resources from any origin."})

    hsts = headers.get("Strict-Transport-Security")
    if hsts is not None:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts.lower())
        if not match:
            vulnerabilities.append({"header": "Strict-Transport-Security",
                                    "issue": "Present, but it carries no max-age directive, so browsers are not told how long to enforce HTTPS."})
        elif int(match.group(1)) == 0:
            vulnerabilities.append({"header": "Strict-Transport-Security",
                                    "issue": "Present, but max-age is 0, which disables Strict Transport Security."})

    xcto = headers.get("X-Content-Type-Options")
    if xcto is not None and xcto.strip().lower() != "nosniff":
        vulnerabilities.append({"header": "X-Content-Type-Options",
                                "issue": "Present, but its value is not nosniff, so MIME type sniffing is not prevented."})

    return vulnerabilities


def main():
    """
    Main function to perform the security header analysis.
    Returns a process exit code: 0 for a completed analysis, 1 when the
    target could not be reached and no analysis was performed.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.max_redirects < 0:
        logging.error("Invalid input: --max-redirects must be 0 or greater.")
        return 1

    url = args.url
    logging.info(f"Starting analysis for URL: {url}")

    request_headers = {}
    if args.user_agent:
        request_headers["User-Agent"] = args.user_agent

    session = requests.Session()
    session.max_redirects = args.max_redirects
    try:
        # No raise_for_status: error responses carry headers too, and
        # analyzing those headers is the purpose of this tool.
        response = session.get(url, headers=request_headers, timeout=REQUEST_TIMEOUT)
        logging.info(f"Received response with status code: {response.status_code}")
    except RequestException as e:
        logging.error(f"Error making request to {url}: {e}")
        logging.error("No response was received, so no header analysis was performed.")
        return 1

    headers = response.headers
    logging.debug(f"Response headers (values masked): {masked_header_log(headers)}")

    vulnerabilities = analyze_headers(headers)

    report_lines = [f"Security header analysis for {url} (status {response.status_code}):"]
    if vulnerabilities:
        report_lines.append("Security vulnerabilities detected:")
        for vuln in vulnerabilities:
            report_lines.append(f"- {vuln['header']}: {vuln['issue']}")
    else:
        report_lines.append("No security vulnerabilities detected in the headers.")

    # Findings never change the exit code. A completed analysis returns 0
    # whether the list above is empty or long; 1 is kept for the runs
    # where no analysis happened at all.
    for line in report_lines:
        logging.info(line)

    if args.output_file:
        try:
            with open(args.output_file, "w") as f:
                f.write("\n".join(report_lines) + "\n")
            logging.info(f"Report written to: {args.output_file}")
        except OSError as e:
            logging.error(f"Could not write output file: {e}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
