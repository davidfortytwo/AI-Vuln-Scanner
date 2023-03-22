import nmap
import openai
import argparse
import os
import sys
import json
import time
from jinja2 import Template
from dotenv import load_dotenv
from bs4 import BeautifulSoup

load_dotenv()

openai.api_key = os.environ.get('OPENAI_API_KEY')
if not openai.api_key:
    openai.api_key = input("Enter your OpenAI API key: ")

    # Save the API key to the .env file
    with open('.env', 'a') as f:
        f.write(f"\nOPENAI_API_KEY={openai.api_key}")

MODEL_ENGINE = "text-davinci-003"
TEMPERATURE = 0.5
TOKEN_LIMIT = 2048
nm = nmap.PortScanner()

parser = argparse.ArgumentParser(description='Python-Nmap and ChatGPT integrated Vulnerability Scanner')
parser.add_argument('-t', '--target', metavar='target', type=str, help='Target IP or hostname', required=True)
parser.add_argument('-o', '--output', metavar='output', type=str, help='Output format (html, csv, xml, txt, json)', default='html')
args = parser.parse_args()

target = args.target
output_format = args.output.lower()

def extract_open_ports(analyze):
    open_ports_info = []
    for host, host_data in analyze.items():
        for key, value in host_data.items():
            if key == "tcp" or key == "udp":
                for port, port_data in value.items():
                    if port_data.get('state') == 'open':
                        open_ports_info.append(f"{key.upper()} Port {port}: {port_data['name']}")
    return ', '.join(open_ports_info)

def scan(ip, arguments):
    nm.scan(ip, arguments)
    json_data = nm.analyse_nmap_xml_scan()
    analyze = json_data["scan"]

    open_ports = extract_open_ports(analyze)

    # Print Nmap scan results on screen
    print("\nNmap Scan Results and Vulnerabilities:")
    for host, host_data in analyze.items():
        print(f"Host: {host}")
        for key, value in host_data.items():
            if key == "hostnames":
                print(f"Hostnames: {', '.join(value)}")
            elif key == "addresses":
                for addr_type, addr in value.items():
                    print(f"{addr_type.capitalize()} Address: {addr}")
            elif key == "tcp" or key == "udp":
                print(f"{key.upper()} Ports:")
                for port, port_data in value.items():
                    print(f"  Port {port}:")
                    for port_key, port_value in port_data.items():
                        print(f"    {port_key.capitalize()}: {port_value}")
            else:
                print(f"{key.capitalize()}: {value}")
        print("\n")

    prompt = f"""
Please perform a vulnerability analysis of the following network scan results:
{analyze}

For each identified vulnerability, include:
1. A detailed description of the vulnerability
2. The correct affected endpoint (host, port, service, etc.)
3. Evidences
4. Relevant references to OWASP ASVS, WSTG, CAPEC, and CWE, with each reference formatted as a clickable hyperlink

Based on the following open ports and services detected:
{open_ports}

Return the results as a well-formatted HTML snippet with line breaks (<br>) separating each section.
"""

    completion = openai.Completion.create(
        engine=MODEL_ENGINE,
        prompt=prompt,
        max_tokens=TOKEN_LIMIT,
        n=1,
        temperature=TEMPERATURE,
        stop=None,
    )
    response = completion.choices[0].text
    # Return both the response and the analyze data
    return response, analyze

def export_to_csv(data, filename):
    import csv
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        writer.writeheader()
        writer.writerow(data)

def export_to_xml(data, filename):
    import xml.etree.ElementTree as ET
    root = ET.Element('VulnerabilityReport')
    for key, value in data.items():
        entry = ET.SubElement(root, key)
        entry.text = str(value)
    tree = ET.ElementTree(root)
    tree.write(filename, encoding='utf-8', xml_declaration=True)

def export_to_txt(data, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        for key, value in data.items():
            f.write(f'{key}: {value}\n')

def export_to_json(data, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def export_to_html(html_snippet, filename):
    template = Template("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Vulnerability Report</title>
            <style>
                {% raw %}
                body { font-family: Arial, sans-serif; }
                h1 { color: #333; }
                pre { white-space: pre-wrap; word-wrap: break-word; }
                {% endraw %}
            </style>
        </head>
        <body>
            <h1>Vulnerability Report</h1>
            {{ html_snippet }}
        </body>
        </html>
    """)
    html_content = template.render(html_snippet=html_snippet)
    with open(filename, "w", encoding='utf-8') as f:
        f.write(html_content)

def is_valid_json(json_string):
    try:
        data = json.loads(json_string)
        return isinstance(data, dict) or (isinstance(data, list) and len(data) > 0)
    except json.JSONDecodeError:
        return False

def main(target, output_format):
    profiles = {
        1: '-Pn -sV -T4 -O -F -vvv',
        2: '-Pn -T4 -A -vvv',
        3: '-Pn -sS -sU -T4 -A -vvv',
        4: '-Pn -p- -T4 -A -vvv',
        5: '-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln -vvv',
        6: '-Pn -sS -sU --script=vulners --min-rate=5000 -p- -vvv'
    }

    print("Available scan profiles:")
    print("1. Fast scan")
    print("2. Comprehensive scan")
    print("3. Stealth scan with UDP")
    print("4. Full port range scan")
    print("5. Stealth and UDP scan with version detection and OS detection")
    print("6. Vulnerability scan against all TCP and UDP ports")

    try:
        profile = int(input("Enter profile of scan: "))
        if profile not in profiles:
            raise ValueError
    except ValueError:
        print("Error: Invalid profile input. Please provide a valid profile number.")
        return

    final, analyze = scan(target, profiles[profile])

    if is_valid_json(final):
        parsed_response = json.loads(final)
        formatted_response = json.dumps(parsed_response, indent=2)
    else:
        formatted_response = final

    # Print Nmap scan results in plain text
    print("\nNmap Scan Results:")
    for host, host_data in analyze.items():
        print(f"Host: {host}")
        for key, value in host_data.items():
            if key == "hostnames":
                print(f"Hostnames: {', '.join(value)}")
            elif key == "addresses":
                for addr_type, addr in value.items():
                    print(f"{addr_type.capitalize()} Address: {addr}")
            elif key == "tcp" or key == "udp":
                print(f"{key.upper()} Ports:")
                for port, port_data in value.items():
                    print(f"  Port {port}:")
                    for port_key, port_value in port_data.items():
                        print(f"    {port_key.capitalize()}: {port_value}")
            else:
                print(f"{key.capitalize()}: {value}")
        print("\n")

    # Parse HTML vulnerability analysis results into plain text
    soup = BeautifulSoup(final, "html.parser")
    plain_text_results = soup.get_text()

    print(plain_text_results)

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"{target}-{timestamp}.{output_format}"

    if output_format == 'html':
        export_to_html(final, filename)
    elif output_format == 'csv':
        export_to_csv(parsed_response, filename)
    elif output_format == 'xml':
        export_to_xml(parsed_response, filename)
    elif output_format == 'txt':
        export_to_txt(parsed_response, filename)
    elif output_format == 'json':
        export_to_json(parsed_response, filename)
    else:
        print(f"Error: Unsupported output format '{output_format}'. Supported formats: html, csv, xml, txt, json")
        return

    print(f"Results have been exported to {filename}")

if __name__ == "__main__":
    main(target, output_format)
