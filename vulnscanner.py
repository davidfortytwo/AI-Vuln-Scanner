#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: cbk914 (refactored by Perplexity AI)

import os
import sys
import argparse
import logging
import time
import json
import requests

try:
    import nmap3
    from jinja2 import Template
    from dotenv import load_dotenv
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"Missing dependency: {e.name}. Please install it with pip.")
    sys.exit(1)

load_dotenv()

# Logging setup (default to INFO, set to DEBUG in main if needed)
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

# AI Provider Configs
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
ANYTHINGLLM_API_KEY = os.getenv('ANYTHINGLLM_API_KEY')
ANYTHINGLLM_API_URL = os.getenv('ANYTHINGLLM_API_URL')
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
REPLIT_API_KEY = os.getenv('REPLIT_API_KEY')
REPLIT_API_URL = os.getenv('REPLIT_API_URL', 'https://chat.replit.com/v1/chat/completions')

MODEL_ENGINE = "gpt-4o"
TEMPERATURE = 0.5
TOKEN_LIMIT = 4096

nm = nmap3.Nmap()

def mask_api_key(key):
    if not key or len(key) < 8:
        return "[NOT SET]"
    return key[:4] + "..." + key[-4:]

def validate_api_keys():
    missing_keys = []
    if not OPENAI_API_KEY:
        missing_keys.append("OPENAI_API_KEY")
    if not ANYTHINGLLM_API_KEY:
        missing_keys.append("ANYTHINGLLM_API_KEY")
    if not ANTHROPIC_API_KEY:
        missing_keys.append("ANTHROPIC_API_KEY")
    if not REPLIT_API_KEY:
        missing_keys.append("REPLIT_API_KEY")

    if missing_keys:
        logging.warning(f"Missing API keys: {', '.join(missing_keys)}. Some functionality may be unavailable.")

    logging.debug(f"OpenAI API Key: {mask_api_key(OPENAI_API_KEY)}")
    logging.debug(f"AnythingLLM API Key: {mask_api_key(ANYTHINGLLM_API_KEY)}")
    logging.debug(f"Anthropic API Key: {mask_api_key(ANTHROPIC_API_KEY)}")
    logging.debug(f"Replit API Key: {mask_api_key(REPLIT_API_KEY)}")

def print_ethical_warning():
    print("\n" + "="*80)
    print("WARNING: Use this script ONLY on systems you own or have explicit permission to test.")
    print("Unauthorized scanning is illegal and unethical.")
    print("="*80 + "\n")

def extract_open_ports(analyze):
    open_ports_info = []
    for host, host_data in analyze.items():
        ports = host_data.get("ports", [])
        for port_entry in ports:
            if port_entry.get('state') == 'open':
                portid = port_entry.get('portid')
                service = port_entry.get('service', {}).get('name', 'unknown')
                protocol = port_entry.get('protocol', 'tcp')
                open_ports_info.append(f"{protocol.upper()} Port {portid}: {service}")
    return ', '.join(open_ports_info)

def print_scan_results(analyze):
    for host, host_data in analyze.items():
        logging.info(f"Host: {host}")
        if "hostname" in host_data:
            logging.info(f"Hostname: {host_data['hostname']}")
        if "ports" in host_data:
            logging.info("Ports:")
            for port_entry in host_data["ports"]:
                portid = port_entry.get('portid')
                protocol = port_entry.get('protocol', 'tcp')
                state = port_entry.get('state')
                service = port_entry.get('service', {}).get('name', 'unknown')
                logging.info(f"  {protocol.upper()} Port {portid}: {service} ({state})")
        print("\n")

def run_nmap_scan(ip, arguments):
    try:
        result = nm.scan_command(arguments, ip)
        if not result or ip not in result:
            logging.error("Nmap scan returned no results.")
            return {}
        analyze = {ip: result[ip]}
        return analyze
    except Exception as e:
        logging.error(f"Nmap scan failed: {e}")
        return {}

def get_user_asset_context_and_threat_intel():
    print("Provide asset context (e.g., 'web server', 'IoT device', 'database', etc.). Leave blank to auto-detect:")
    asset_context = input("Asset context: ").strip()
    print("Provide any recent threat intelligence (e.g., 'CVE-2025-1234 is being exploited', etc.). Leave blank to auto-enrich:")
    threat_intel = input("Threat intelligence: ").strip()
    return asset_context, threat_intel

def auto_deduce_asset_context(analyze, open_ports):
    ports = open_ports.lower()
    if "http" in ports or "80" in ports or "443" in ports:
        return "web server"
    if "mysql" in ports or "postgres" in ports or "3306" in ports or "5432" in ports:
        return "database server"
    if "rdp" in ports or "3389" in ports:
        return "remote desktop server"
    if "ssh" in ports or "22" in ports:
        return "linux/unix server"
    if "smb" in ports or "445" in ports:
        return "windows file server"
    return "networked device"

def auto_enrich_threat_intel(analyze, open_ports):
    return "No specific active threat intelligence found for these services. Ensure to check recent CVE advisories."

def list_anythingllm_models():
    if not ANYTHINGLLM_API_URL or not ANYTHINGLLM_API_KEY:
        logging.error("AnythingLLM API URL or API Key not set.")
        return []
    url = f"{ANYTHINGLLM_API_URL}/models"
    headers = {'Authorization': f'Bearer {ANYTHINGLLM_API_KEY}'}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        models = response.json().get("models", [])
        return models
    except Exception as e:
        logging.error(f"Failed to fetch models from AnythingLLM: {e}")
        return []

def ask_anythingllm(prompt, model):
    url = f"{ANYTHINGLLM_API_URL}/chat"
    headers = {
        'Authorization': f'Bearer {ANYTHINGLLM_API_KEY}',
        'Content-Type': 'application/json'
    }
    data = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a cybersecurity expert."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": TOKEN_LIMIT,
        "temperature": TEMPERATURE
    }
    try:
        response = requests.post(url, headers=headers, json=data, timeout=60)
        response.raise_for_status()
        result = response.json()
        return result.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        logging.error(f"AnythingLLM API error: {e}")
        return "<b>AnythingLLM API error. No vulnerability analysis available.</b>"

def ask_openai(prompt):
    import openai
    openai.api_key = OPENAI_API_KEY
    try:
        response = openai.ChatCompletion.create(
            model=MODEL_ENGINE,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=TOKEN_LIMIT,
            temperature=TEMPERATURE,
        )
        return response.choices[0].message.content
    except Exception as e:
        logging.error(f"OpenAI API error: {e}")
        return "<b>OpenAI API error. No vulnerability analysis available.</b>"

def ask_anthropic(prompt):
    # Claude 3 API (Anthropic)
    if not ANTHROPIC_API_KEY:
        logging.error("Anthropic API key not set.")
        return "<b>No Anthropic API key configured.</b>"
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    data = {
        "model": "claude-3-opus-20240229",  # Or use "claude-3-sonnet-20240229" or "claude-3-haiku-20240307"
        "max_tokens": TOKEN_LIMIT,
        "temperature": TEMPERATURE,
        "system": "You are a cybersecurity expert.",
        "messages": [{"role": "user", "content": prompt}]
    }
    try:
        response = requests.post(url, headers=headers, json=data, timeout=60)
        response.raise_for_status()
        result = response.json()
        return result.get("content", "")
    except Exception as e:
        logging.error(f"Anthropic API error: {e}")
        return "<b>Anthropic API error. No vulnerability analysis available.</b>"

def ask_replit(prompt):
    # Replit AI (Assume OpenAI-compatible endpoint)
    if not REPLIT_API_KEY:
        logging.error("Replit API key not set.")
        return "<b>No Replit API key configured.</b>"
    headers = {
        "Authorization": f"Bearer {REPLIT_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "replit-code-v1-3b",  # Or allow user to select if multiple models supported
        "messages": [
            {"role": "system", "content": "You are a cybersecurity expert."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": TOKEN_LIMIT,
        "temperature": TEMPERATURE
    }
    try:
        response = requests.post(REPLIT_API_URL, headers=headers, json=data, timeout=60)
        response.raise_for_status()
        result = response.json()
        return result.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        logging.error(f"Replit API error: {e}")
        return "<b>Replit API error. No vulnerability analysis available.</b>"

def ask_ai_vuln_analysis(analyze, open_ports, asset_context, threat_intel, provider=None):
    prompt = f"""
You are a cybersecurity expert. Analyze the following nmap scan results:

{analyze}

Asset context: {asset_context if asset_context else 'Auto-deduce and enrich context based on open ports/services.'}
Threat intelligence: {threat_intel if threat_intel else 'Auto-enrich with current threat intelligence and recent CVEs.'}

For each open port/service, provide:
1. A description of potential vulnerabilities
2. The affected endpoint (host, port, service)
3. Evidence from the scan
4. Severity rating (Critical, High, Medium, Low) and a brief rationale
5. Remediation steps
6. References to OWASP ASVS, WSTG, CAPEC, CWE (as clickable links)

Prioritize findings by risk to the business, and highlight any issues that are currently being exploited in the wild (if known).

Based on the following open ports and services detected:
{open_ports}

Return the results as a well-formatted HTML snippet with line breaks (<br>) separating each section.
"""
    available_providers = []
    if ANYTHINGLLM_API_URL and ANYTHINGLLM_API_KEY:
        available_providers.append("AnythingLLM")
    if OPENAI_API_KEY:
        available_providers.append("OpenAI")
    if ANTHROPIC_API_KEY:
        available_providers.append("Anthropic")
    if REPLIT_API_KEY:
        available_providers.append("Replit")

    if not provider:
        if len(available_providers) == 0:
            return "<b>No AI provider configured. Set ANYTHINGLLM_API_KEY/URL, OPENAI_API_KEY, ANTHROPIC_API_KEY, or REPLIT_API_KEY.</b>"
        if len(available_providers) == 1:
            provider = available_providers[0]
        else:
            print("\nAvailable AI providers:")
            for idx, name in enumerate(available_providers, 1):
                print(f"{idx}. {name}")
            while True:
                try:
                    sel = int(input("Select AI provider: "))
                    if 1 <= sel <= len(available_providers):
                        provider = available_providers[sel-1]
                        break
                    else:
                        print("Invalid selection. Try again.")
                except Exception:
                    print("Invalid input. Try again.")

    if provider == "AnythingLLM":
        models = list_anythingllm_models()
        if not models:
            logging.error("No models available from AnythingLLM.")
            return "<b>No models available from AnythingLLM.</b>"
        print("\nAvailable AnythingLLM models:")
        for idx, m in enumerate(models, 1):
            print(f"{idx}. {m}")
        while True:
            try:
                model_idx = int(input("Select model number to use for analysis: "))
                if 1 <= model_idx <= len(models):
                    selected_model = models[model_idx - 1]
                    break
                else:
                    print("Invalid selection. Try again.")
            except Exception:
                print("Invalid input. Try again.")
        print(f"Using AnythingLLM model: {selected_model}")
        return ask_anythingllm(prompt, selected_model)
    elif provider == "OpenAI":
        return ask_openai(prompt)
    elif provider == "Anthropic":
        return ask_anthropic(prompt)
    elif provider == "Replit":
        return ask_replit(prompt)
    else:
        return "<b>No valid AI provider selected.</b>"

def is_valid_json(json_string):
    try:
        data = json.loads(json_string)
        return isinstance(data, dict) or (isinstance(data, list) and len(data) > 0)
    except json.JSONDecodeError:
        return False

def export_to_csv(data, filename):
    import csv
    if not isinstance(data, dict):
        logging.warning("CSV export expects a dictionary. Skipping export.")
        return
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        writer.writeheader()
        writer.writerow(data)

def export_to_xml(data, filename):
    import xml.etree.ElementTree as ET
    root = ET.Element('VulnerabilityReport')
    if isinstance(data, dict):
        for key, value in data.items():
            entry = ET.SubElement(root, key)
            entry.text = str(value)
    else:
        entry = ET.SubElement(root, "data")
        entry.text = str(data)
    tree = ET.ElementTree(root)
    tree.write(filename, encoding='utf-8', xml_declaration=True)

def export_to_txt(data, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        if isinstance(data, dict):
            for key, value in data.items():
                f.write(f'{key}: {value}\n')
        else:
            f.write(str(data))

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
                body { font-family: Arial, sans-serif; }
                h1 { color: #333; }
                pre { white-space: pre-wrap; word-wrap: break-word; }
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

def main():
    banner = r"""
 █████╗ ██╗    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██║    ██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████║██║    ██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔══██║██║    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║  ██║██║     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝╚═╝      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
by cbk914
"""
    print(banner)
    print_ethical_warning()

    # Validate API keys early
    validate_api_keys()

    profiles = {
        1: ('Fast scan', '-Pn -sV -T4 -O -F -vvv'),
        2: ('Comprehensive scan', '-Pn -T4 -A -vvv'),
        3: ('Stealth scan with UDP', '-Pn -sS -sU -T4 -A -vvv'),
        4: ('Full port range scan', '-Pn -p- -T4 -A -vvv'),
        5: ('Stealth and UDP scan with version detection and OS detection', '-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln -vvv'),
        6: ('Vulnerability scan against all TCP and UDP ports', '-Pn -sS -sU --script=vulners --min-rate=5000 -p- -vvv'),
        7: ('WAF bypass scan against all TCP ports', '-Pn -T2 -f --mtu 16 -vvv'),
        8: ('Misconfigured firewall bypass', '-sF -T4 -p- --script firewall-bypass -vvv')
    }

    profile_list = "\n".join(f"{num}. {desc}" for num, (desc, _) in profiles.items())

    parser = argparse.ArgumentParser(
        description='Python-Nmap3 and Multi-AI (OpenAI, AnythingLLM, Anthropic, Replit) Vulnerability Scanner',
        epilog=f"Available scan profiles:\n{profile_list}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-t', '--target', metavar='target', type=str, help='Target IP or hostname', required=True)
    parser.add_argument('-o', '--output', metavar='output', type=str, help='Output format (html, csv, xml, txt, json)', default='html')
    parser.add_argument('-p', '--profile', metavar='profile', type=int, help='Scan profile number (1-8)', required=False)
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')

    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug mode enabled.")

    target = args.target
    output_format = args.output.lower()
    profile_num = args.profile

    if profile_num not in profiles:
        print("Available scan profiles:")
        for num, (desc, _) in profiles.items():
            print(f"{num}. {desc}")
        try:
            profile_num = int(input("Enter profile number of scan: "))
            if profile_num not in profiles:
                raise ValueError
        except ValueError:
            logging.error("Invalid profile input. Please provide a valid profile number.")
            return

    scan_desc, scan_args = profiles[profile_num]
    logging.info(f"Selected scan profile: {scan_desc}")
    logging.debug(f"Scan arguments: {scan_args}")
    logging.debug(f"Target: {target}")

    root_profiles = [7, 8]
    if profile_num in root_profiles and os.geteuid() != 0:
        print("\n[WARNING] The selected scan profile requires root privileges (sudo).")
        print("Please re-run this script as root (sudo) to use this scan profile.\n")
        sys.exit(1)

    logging.debug("Starting nmap scan...")
    analyze = run_nmap_scan(target, scan_args)
    logging.debug(f"Nmap scan result: {json.dumps(analyze, indent=2)}")

    if not analyze:
        logging.error("No scan results. Exiting.")
        return

    print_scan_results(analyze)
    open_ports = extract_open_ports(analyze)
    logging.debug(f"Open ports: {open_ports}")

    asset_context, threat_intel = get_user_asset_context_and_threat_intel()
    if not asset_context:
        asset_context = auto_deduce_asset_context(analyze, open_ports)
        logging.debug(f"Auto-deduced asset context: {asset_context}")
        print(f"Auto-deduced asset context: {asset_context}")
    if not threat_intel:
        threat_intel = auto_enrich_threat_intel(analyze, open_ports)
        logging.debug(f"Auto-enriched threat intelligence: {threat_intel}")
        print(f"Auto-enriched threat intelligence: {threat_intel}")

    logging.debug("Sending scan results to AI for analysis...")
    vuln_html = ask_ai_vuln_analysis(analyze, open_ports, asset_context, threat_intel)
    logging.debug(f"AI analysis (HTML): {vuln_html}")

    soup = BeautifulSoup(vuln_html, "html.parser")
    plain_text_results = soup.get_text()
    print("\n[AI Vulnerability Analysis]\n")
    print(plain_text_results)

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"{target}-{timestamp}.{output_format}"

    parsed_response = None
    if is_valid_json(vuln_html):
        parsed_response = json.loads(vuln_html)
    else:
        parsed_response = {"vulnerability_analysis": plain_text_results}

    logging.debug(f"Exporting results to {filename} as {output_format}")
    if output_format == 'html':
        export_to_html(vuln_html, filename)
    elif output_format == 'csv':
        export_to_csv(parsed_response, filename)
    elif output_format == 'xml':
        export_to_xml(parsed_response, filename)
    elif output_format == 'txt':
        export_to_txt(parsed_response, filename)
    elif output_format == 'json':
        export_to_json(parsed_response, filename)
    else:
        logging.error(f"Unsupported output format '{output_format}'. Supported formats: html, csv, xml, txt, json")
        return

    logging.info(f"Results have been exported to {filename}")

if __name__ == "__main__":
    main()

