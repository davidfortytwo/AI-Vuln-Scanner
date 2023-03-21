import nmap
import openai
import argparse
import os
import sys

openai.api_key = os.environ.get('OPENAI_API_KEY')
if not openai.api_key:
    sys.exit("Error: Missing OPENAI_API_KEY environment variable")

model_engine = "text-davinci-003"
nm = nmap.PortScanner()

parser = argparse.ArgumentParser(description='Python-Nmap and ChatGPT integrated Vulnerability Scanner')
parser.add_argument('target', metavar='target', type=str, help='Target IP or hostname')
args = parser.parse_args()

target = args.target


def scan(ip, arguments):
    nm.scan(ip, arguments)
    json_data = nm.analyse_nmap_xml_scan()
    analyze = json_data["scan"]

    prompt = "do a vulnerability analysis of {} and return a vulnerability report in json".format(analyze)

    completion = openai.Completion.create(
        engine=model_engine,
        prompt=prompt,
        max_tokens=1024,
        n=1,
        stop=None,
    )
    response = completion.choices[0].text
    return response


def main(target):
    profiles = {
        1: '-Pn -sV -T4 -O -F',
        2: '-Pn -T4 -A -v',
        3: '-Pn -sS -sU -T4 -A -v',
        4: '-Pn -p- -T4 -A -v',
        5: '-Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln'
        6: '-Pn -sV --min-rate=5000 --script=vulners'
    }

    print("Available scan profiles:")
    print("1. Fast scan")
    print("2. Comprehensive scan")
    print("3. Stealth scan with UDP")
    print("4. Full port range scan")
    print("5. Stealth and UDP scan with version detection and OS detection")
    print("6. Vulnerability scan")

    try:
        profile = int(input("Enter profile of scan: "))
        if profile not in profiles:
            raise ValueError
    except ValueError:
        print("Error: Invalid profile input. Please provide a valid profile number.")
        return

    final = scan(target, profiles[profile])
    print(final)


if __name__ == "__main__":
    main(target)
