## vuln-Security-Header-Analyzer

### Project Description

vuln-Security-Header-Analyzer is a tool designed to analyze HTTP response headers for potential security vulnerabilities. It checks whether each security header is present, and it also judges the values of the headers whose posture is value defined: X-Frame-Options must be DENY or SAMEORIGIN, Content-Security-Policy must not allow unsafe-inline, unsafe-eval, or a wildcard source, Strict-Transport-Security must carry a non-zero max-age, and X-Content-Type-Options must be nosniff. Headers are analyzed on every response received, including error responses. Verbose mode logs header names with masked values only, so cookie and authorization values are never printed in clear.

### Installation Instructions

1. Clone the repository:
   ```
   git clone https://github.com/ShadowStrikeHQ/vuln-Security-Header-Analyzer.git
   ```
2. Navigate to the project directory:
   ```
   cd vuln-Security-Header-Analyzer
   ```
3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

### Usage Examples

**Basic Usage:**

```
python main.py <URL>
```

**Example with Custom User-Agent Header:**

```
python main.py <URL> --user-agent "MyCustomUserAgent"
```

**Example with Maximum HTTP Redirects:**

```
python main.py <URL> --max-redirects 10
```

**Example with Output File Path:**

```
python main.py <URL> --output-file /path/to/output.txt
```

### Security Warnings and Considerations

* Scan results may vary depending on the specific web application configuration.
* False positives may occur, so manual verification of findings is recommended.
* Ensure that the tool is used in a secure environment to prevent unauthorized access or modification of scan data.

### License

This tool is released under the GNU General Public License v3.0.