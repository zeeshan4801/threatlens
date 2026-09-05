# 🛡️ ThreatLens

## Free Cybersecurity Intelligence Analyzer

ThreatLens is a lightweight cybersecurity reconnaissance tool built with
Python and Streamlit.

It analyzes domains, IP addresses, and URLs using free security checks
such as:

-   DNS resolution
-   SSL certificate validation
-   WHOIS lookup
-   Basic risk assessment

## Project Structure

    ThreatLens/
    │
    ├── app.py
    ├── sources.py
    ├── requirements.txt
    ├── README.md
    └── .gitignore

## Features

### Target Analysis

Supports: - Domains - IP addresses - URLs

### DNS Intelligence

-   Domain resolution
-   IP discovery
-   Connectivity checks

### SSL Analysis

-   Certificate validation
-   Issuer details
-   Validity information

### WHOIS Intelligence

-   Registrar information
-   Country
-   Creation date
-   Domain metadata

## Architecture

ThreatLens uses a modular source registry architecture.

New intelligence sources can be added by creating one function and
registering it without changing the main application.

Future integrations: - VirusTotal - AbuseIPDB - Shodan - GreyNoise -
URLScan

## Installation

Install dependencies:

``` bash
pip install -r requirements.txt
```

## Run Application

``` bash
streamlit run app.py
```

Open:

    http://localhost:8501

## Google Colab Deployment

Run Streamlit:

``` bash
streamlit run app.py --server.port 8501
```

Create Cloudflare public tunnel:

``` bash
cloudflared tunnel --url http://localhost:8501
```

## Requirements

    streamlit
    python-whois
    requests
    validators

## Security Design

-   No hardcoded secrets
-   Lightweight dependencies
-   Modular architecture
-   Error handling
-   Defensive security focus

## Disclaimer

ThreatLens is created for educational and defensive cybersecurity
purposes only.

Always obtain authorization before analyzing systems or domains.

## Author

ThreatLens Project
