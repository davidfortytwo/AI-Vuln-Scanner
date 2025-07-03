# AI-Vuln-Scanner

**AI-Vuln-Scanner** is a Python-based, AI-integrated vulnerability scanner that combines the power of Nmap (via `python3-nmap`), multiple leading AI models (OpenAI, Anthropic Claude, Replit AI, and AnythingLLM), and modern reporting. It performs advanced network scans, then uses AI to analyze results, prioritize risks, and suggest remediations with references to security standards (OWASP ASVS, WSTG, CAPEC, CWE).

---

## Key Features

- **Multiple AI Providers:** Supports OpenAI (GPT-4o), Anthropic Claude, Replit AI, and AnythingLLM. User can select provider and model at runtime.
- **Asset Context & Threat Intelligence:** User can provide or auto-deduce asset type and threat intelligence for more relevant analysis.
- **Scan Profiles:** Eight built-in scan profiles (e.g., Fast, Full, WAF bypass, Vulnerability scan).
- **Rich Output:** Exports to HTML, CSV, XML, TXT, or JSON.
- **Risk Prioritization & Remediation:** AI provides severity, rationale, and actionable remediation for each finding.
- **Debug Mode:** Use `-d` to see detailed debug logs and scan commands.
- **Root Privilege Check:** Warns if root is required for selected scan profile.
- **Interactive & Scriptable:** All options can be provided via command line or interactively.

---

## Installation

1. **Install Python 3.x**  
   [Download Python](https://www.python.org/downloads/)

2. **Clone this repository:**
    ```
    git clone https://github.com/davidfortytwo/AI-Vuln-Scanner.git
    cd AI-Vuln-Scanner
    ```

3. **Install dependencies:**
    ```
    pip install -r requirements.txt
    ```

4. **Configure your `.env` file:**  
   Copy `.env-example` to `.env` and fill in your API keys as needed:

    ```
    cp .env-example .env
    # Edit .env with your keys and endpoints
    ```

---

## Configuration

**.env-example:**
  ```
  OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  
  ANYTHINGLLM_API_KEY=your_anythingllm_api_key
  
  ANYTHINGLLM_API_URL=http://localhost:3001/api/v1
  
  ANTHROPIC_API_KEY=your_anthropic_api_key
  
  REPLIT_API_KEY=your_replit_api_key
  
  REPLIT_API_URL=https://chat.replit.com/v1/chat/completions
  ```

- Set only the providers you want to use.  
- If multiple are set, you’ll be prompted to choose at runtime.

---

## Usage

### Basic Example

  python vulnscanner.py -t target_ip_or_hostname -o output_format


- `-t` Target IP or hostname (required)
- `-o` Output format: html, csv, xml, txt, or json (default: html)
- `-p` Scan profile number (see below)
- `-d` Enable debug mode (verbose output)

### Example: Fast Scan with OpenAI
  ```
  python vulnscanner.py -t 192.168.1.1 -o html -p 1
  ```

### Example: WAF Bypass Scan (requires root)

  ```
  sudo python vulnscanner.py -t example.com -o html -p 7
  ```

### Example: Debug Mode
  ```
  python vulnscanner.py -t 192.168.1.1 -o json -p 2 -d
  ```

### Example: Using Anthropic Claude

Set your `ANTHROPIC_API_KEY` in `.env` and run:

  ```
  python vulnscanner.py -t 192.168.1.1 -o html -p 2
  ```
Select "Anthropic" when prompted for AI provider


### Example: Using AnythingLLM

Set `ANYTHINGLLM_API_KEY` and `ANYTHINGLLM_API_URL` in `.env` and run:

  ```
  python vulnscanner.py -t 192.168.1.1 -o html -p 2
  ```

Select "AnythingLLM" and then select the desired model when prompted

---

## Scan Profiles

You can select from the following scan profiles (shown in help and at runtime):

1. Fast scan  
2. Comprehensive scan  
3. Stealth scan with UDP  
4. Full port range scan  
5. Stealth and UDP scan with version detection and OS detection  
6. Vulnerability scan against all TCP and UDP ports  
7. WAF bypass scan against all TCP ports (requires root)  
8. Misconfigured firewall bypass (requires root)  

---

## Asset Context & Threat Intelligence

- You will be prompted to specify the asset type (e.g., "web server", "IoT device") and any current threat intelligence (e.g., "CVE-2025-1234 is being exploited").
- If left blank, the script will auto-deduce/enrich this information based on scan results and common ports.

---

## Output

- Results are displayed in the terminal and saved to a timestamped file in your chosen format.
- Each finding includes:  
  - Vulnerability description  
  - Affected endpoint  
  - Evidence  
  - Severity rating and rationale  
  - Remediation steps  
  - References to OWASP ASVS, WSTG, CAPEC, and CWE (as clickable links)  
  - Risk prioritization and exploitation status

---

## Debug Mode

Add `-d` to any command to enable debug output.  
This will show:
- The actual nmap command being run
- All intermediate data (scan results, AI prompts, etc.)
- API provider/model selection and responses

---

## Multi-AI Support

The scanner supports:
- **OpenAI (GPT-4o and compatible)**
- **AnythingLLM** (self-hosted, supports many models)
- **Anthropic Claude**
- **Replit AI**

You can set up one or more providers in your `.env` file and select at runtime.

---

## Disclaimer of Liability

The AI-Integrated Vulnerability Scanner is provided as-is, without any guarantees or warranties, either express or implied. By using this tool, you acknowledge that you are solely responsible for any consequences that may arise from its usage.

The tool is intended for educational purposes, ethical security assessments, and to help you identify potential vulnerabilities in your network or systems. It is strictly prohibited to use the AI-Integrated Vulnerability Scanner for malicious activities, unauthorized access, or any other illegal activities.

By using the AI-Integrated Vulnerability Scanner, you agree to assume full responsibility for your actions and the results generated by the tool. The developers and contributors of this project shall not be held liable for any damages or losses, whether direct, indirect, incidental, or consequential, arising from the use or misuse of this tool.

It is your responsibility to ensure that you have the proper authorization and consent before scanning any network or system. You must also comply with all applicable laws, regulations, and ethical guidelines related to network scanning and vulnerability assessment.

By using the AI-Integrated Vulnerability Scanner, you acknowledge and accept the terms stated in this Disclaimer of Liability. If you do not agree with these terms, you must not use this tool.

---

**Enjoy advanced, AI-powered vulnerability scanning!**  
For questions, feature requests, or contributions, please open an issue or PR.
