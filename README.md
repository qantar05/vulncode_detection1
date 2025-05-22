# CWE Analyzer

A static code analysis tool that identifies potential vulnerabilities and maps them to Common Weakness Enumeration (CWE) IDs using the CWE REST API.

## Features

- Analyzes code for potential security vulnerabilities
- Maps identified issues to CWE IDs
- Retrieves detailed information from the CWE REST API
- Supports multiple programming languages (Python, JavaScript, Java, C/C++)
- Generates reports in different formats (text, JSON, Markdown)
- Caches API responses for better performance

## Installation

1. Clone this repository:
   ```
   git clone <repository-url>
   cd cwe-analyzer
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Command Line Interface

Analyze a single file:
```
python analyze_code.py path/to/file.py
```

Analyze a directory:
```
python analyze_code.py path/to/directory
```

Generate a report in a specific format:
```
python analyze_code.py path/to/file.py --format markdown --output report.md
```

Available formats:
- `text` (default): Plain text output
- `json`: JSON format for machine processing
- `markdown`: Markdown format for human-readable reports

### Python API

You can also use the analyzer in your own Python code:

```python
from cwe_analyzer import CWEAnalyzer

# Create an analyzer
analyzer = CWEAnalyzer()

# Analyze a file
results = analyzer.analyze_file("path/to/file.py")

# Process the results
for result in results:
    print(f"Line {result['line']}: {result['cwe_name']} (CWE-{result['cwe_id']})")
    print(f"  {result['code']}")
    print(f"  Severity: {result['severity']}")
```

## CWE REST API

This tool uses the CWE REST API provided by MITRE to retrieve detailed information about CWE IDs. The API is available at `https://cwe-api.mitre.org/api/v1/`.

Key endpoints used:
- `/cwe/version` - Get CWE version information
- `/cwe/weakness/{id}` - Get detailed information about a specific weakness
- `/cwe/{id}/parents` - Get the parents of a CWE
- `/cwe/{id}/children` - Get the children of a CWE

For more information about the CWE REST API, see the [Quick Start Instructions](https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md).

## Example

The repository includes a sample vulnerable code file (`vulnerable_sample.py`) that you can use to test the analyzer:

```
python analyze_code.py vulnerable_sample.py --format markdown --output report.md
```

This will generate a report identifying the vulnerabilities in the sample code.

## Supported Vulnerability Types

The analyzer can detect various types of vulnerabilities, including:

- SQL Injection (CWE-89)
- Cross-site Scripting (CWE-79)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- Insecure Deserialization (CWE-502)
- Hardcoded Credentials (CWE-798)
- Weak Cryptography (CWE-327)
- Buffer Overflow (CWE-120)
- Format String Vulnerability (CWE-134)
- And more...

## Limitations

- The analyzer uses pattern matching, which may result in false positives or false negatives
- It does not perform data flow analysis or context-sensitive analysis
- The accuracy depends on the patterns defined in the code

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- MITRE for providing the CWE REST API
- The CWE community for maintaining the Common Weakness Enumeration
