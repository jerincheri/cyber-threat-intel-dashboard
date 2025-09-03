cat > README.md << 'EOF'
# Cyber Threat Intelligence Dashboard

A Flask-based web dashboard for cyber threat intelligence analysis with API integrations for VirusTotal, AbuseIPDB, and AlienVault OTX.

![CTI Dashboard](https://img.shields.io/badge/Flask-2.3.3-green) ![MongoDB](https://img.shields.io/badge/MongoDB-5.0-green) ![Python](https://img.shields.io/badge/Python-3.8%2B-blue)

## Features

- 🔍 **Threat Lookup**: Search for IP addresses, domains, and file hashes
- 📊 **Multi-source Intelligence**: Integrates VirusTotal, AbuseIPDB, and AlienVault OTX
- 📈 **Data Visualization**: Interactive charts with Chart.js
- 📁 **Export Functionality**: Download reports in CSV and PDF formats
- 🏷️ **IOC Tagging System**: Categorize indicators with custom tags
- 💾 **MongoDB Storage**: Persistent data storage
- 📱 **Responsive Design**: Works on desktop and mobile
- 🌙 **Dark/Light Mode**: Toggle between themes
- 🎨 **Bootstrap 5 UI**: Modern, professional interface

## Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/cyber-threat-intel-dashboard.git
cd cyber-threat-intel-dashboard
```
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

sudo apt install mongodb
sudo systemctl start mongodb

python app.py

Open your browser and navigate to http://localhost:5000
API Keys
The application uses the following APIs:

VirusTotal: Get your API key from https://www.virustotal.com/

AbuseIPDB: Get your API key from https://www.abuseipdb.com/

AlienVault OTX: Get your API key from https://otx.alienvault.com/

Replace the placeholder API keys in app.py with your actual keys.

Usage
Dashboard: View statistics and recent threat lookups

Threat Lookup: Enter an IP, domain, or hash to query threat intelligence APIs

Trends: Visualize threat data with interactive charts

Export: Download threat data in CSV or PDF format

Project Structure
text
cyber-threat-intel-dashboard/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/            # HTML templates
│   ├── base.html         # Base template
│   ├── index.html        # Dashboard page
│   ├── lookup.html       # Threat lookup page
│   └── trends.html       # Trends visualization page
├── static/               # Static assets
│   ├── css/              # CSS files
│   └── js/               # JavaScript files
└── README.md             # Project documentation
API Documentation
VirusTotal API Documentation

AbuseIPDB API Documentation

AlienVault OTX API Documentation

Contributing
Fork the repository

Create a feature branch

Make your changes

Submit a pull request




