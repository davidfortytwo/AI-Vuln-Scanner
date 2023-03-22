# AI-Vuln-Scanner

This AI-Integrated Vulnerability Scanner is a Python-based script that combines the power of Nmap, a popular network scanner, with OpenAI's ChatGPT, a state-of-the-art natural language processing model. The tool performs network scans using various profiles and provides a vulnerability analysis based on the scan results. The analysis includes a detailed description of the vulnerabilities, affected endpoints, evidences, and relevant references to OWASP ASVS, WSTG, CAPEC, and CWE. The tool supports multiple output formats, including HTML, CSV, XML, TXT, and JSON.

# Installation

1. Install Python 3.x from https://www.python.org/downloads/

2. Download or clone the AI-Vuln-Scanner repository.

3.  Navigate to the project's root folder in the terminal.

4. Install the required packages using pip:

    pip install -r requirements.txt

5. Add your OpenAI API key to a .env file in the root folder:

    OPENAI_API_KEY=your_api_key_here

Replace your_api_key_here with your actual OpenAI API key.

# Execution

1. Open a terminal and navigate to the project's root folder.

2. Run the script with the required target and optional output format:
    
    python vulnscanner.py -t target_ip_or_hostname -o output_format

Replace target_ip_or_hostname with the target's IP address or hostname, and output_format with the desired output format (html, csv, xml, txt, or json). If no output format is specified, the default format is 'html'.

3. Choose a scan profile from the available options (Fast scan, Comprehensive scan, Stealth scan with UDP, Full port range scan, or Stealth and UDP scan with version detection and OS detection) by entering the corresponding number.
The script will perform the scan and display the results on the screen. It will also save the results in a file with the specified output format in the project's root folder.

Example:

    python vulnscanner.py -t 192.168.1.1 -o html

This command will perform a vulnerability scan on the IP address 192.168.1.1 and save the results in an HTML file.
