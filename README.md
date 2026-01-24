#  About the  *"CYS-ilm Reconnaissance Tool"*

This is a professional security reconnaissance tool developed by CYS-ILM Security Team that systematically analyzes target domains and IP addresses. 
It combines passive information gathering with active discovery techniques to provide comprehensive security assessments for corporate environments. 
The tool generates detailed professional reports to help security teams identify potential vulnerabilities and infrastructure weaknesses before attackers do.

##  2. Key Features:

- *Dual Reconnaissance Approach:* Performs both passive data collection (WHOIS, DNS records) and active network scanning (port discovery, service identification)
- *Intelligent Technology Detection:* Automatically identifies web technologies, frameworks, and server configurations from exposed services
- *Professional Reporting:* Generates multiple output formats (text, HTML, JSON) with executive summaries and risk assessments
- *Optimized Performance:* Uses threading and intelligent rate limiting for efficient scanning without overwhelming targets
- *Security Compliance:* Includes built-in checks for common security headers, SSL/TLS configurations, and exposed sensitive files
- *Risk Assessment Engine:* Automatically calculates risk scores based on findings and provides actionable recommendations
- *Corporate-Ready Design:* Includes proper logging, error handling, and modular architecture suitable for enterprise security workflows


##  3- Project Structure:

          ~/Desktop/recon-tool/
          ├── main.py                          # Main entry point
          ├── requirements.txt                 # Python dependencies
          ├── README.md                        # Documentation
          ├── config.ini                       # Configuration file
          ├── modules/
          │   ├── __init__.py
          │   ├── passive_recon.py            # Enhanced passive recon
          │   ├── active_recon.py             # Enhanced active recon
          │   ├── reporting.py                # Professional reporting
          │   └── utilities.py                # Common utilities
          ├── utils/
          │   ├── __init__.py
          │   ├── logger.py                   # Advanced logging
          │   ├── validator.py                # Input validation
          │   └── exceptions.py               # Custom exceptions
          ├── templates/
          │   ├── html_report.html           # Professional HTML template
          │   └── text_report.txt            # Text template
          └── outputs/                       # Reports directory


# 🚀 Quick Installation (Linux)

## **Step 1: Clone the Tool**

    https://github.com/CYS-ilm/CYS-ilm_Recon_Tool.git
    cd CYS-ilm_Recon_Tool

## **Step 2: Create Virtual Environment**

    python3 -m venv venv

## **Step 3: Activate Virtual Environment**

    source venv/bin/activate

*You'll see `(venv)` appear at start of terminal line*

## **Step 4: Install Requirements**

    pip install -r requirements.txt

## **Step 5: Verify Installation**

    python3 cysilm_recon_tool.py --help

**When done:** Type `deactivate` to exit virtual environment.


#  USAGE EXAMPLES:

  ### Full comprehensive scan
    python3 cysilm_recon_tool.py example.com --all --output html
  
  ### Passive reconnaissance only
    python3 cysilm_recon_tool.py example.com --passive --dns --subdomains --output txt
  
  ### Active reconnaissance only
    python3 cysilm_recon_tool.py example.com --active --scan --tech --output txt
  
  ### Quick security assessment
    python3 cysilm_recon_tool.py example.com --quick --output html
  
  ### Custom port scan
    python3 cysilm_recon_tool.py example.com --active --ports 1-1000 --scan-type quick --output html
  
  ### Specific modules only
    python3 cysilm_recon_tool.py example.com --whois --dns --tech -v --output txt

## ** Author**
Developed by CYS-ilm with the help of AI.

## **⚠️ Disclaimer**
This tool is for **educational purposes and authorized security testing only**. Always obtain explicit permission before scanning any system. The developers are not responsible for misuse.
