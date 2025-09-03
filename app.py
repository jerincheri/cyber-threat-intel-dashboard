from flask import Flask, render_template, request, jsonify, send_file
from flask_pymongo import PyMongo
from datetime import datetime
import requests
import json
import csv
from io import StringIO, BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import threading
import time
from bson import ObjectId

app = Flask(__name__)

# MongoDB configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/threat_intel_db"
mongo = PyMongo(app)

# API Keys (Replace with your actual keys)
VIRUSTOTAL_API_KEY = "41a599bae7daf9e0dde06bbf6da27d52924f3dd187b931d318f0a25a446e3567"
ABUSEIPDB_API_KEY = "1e52632884bce3e18719e72c86c0ca0b002205d399ed4148525bd989e3731a01d4e9b15ecf06ecf6"
ALIENVAULT_API_KEY = "5cb13ee75e1a58da9369dd8861f5e4da46f722447408733269b58ecd7c826557"

# Global variables for dashboard stats
dashboard_stats = {
    "total_lookups": 0,
    "high_severity": 0,
    "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}

# Update dashboard stats
def update_dashboard_stats():
    total_lookups = mongo.db.threat_lookups.count_documents({})
    high_severity = mongo.db.threat_lookups.count_documents({"threat_level": "High"})
    
    dashboard_stats["total_lookups"] = total_lookups
    dashboard_stats["high_severity"] = high_severity
    dashboard_stats["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Helper function to get tags for an indicator
def get_tags_for_indicator(indicator):
    lookups = list(mongo.db.threat_lookups.find({'indicator': indicator}))
    tags = set()
    
    for lookup in lookups:
        if 'tags' in lookup:
            tags.update(lookup['tags'])
    
    return list(tags)

# Home/Dashboard route
@app.route('/')
def index():
    update_dashboard_stats()
    # Get recent lookups for the dashboard
    recent_lookups = list(mongo.db.threat_lookups.find().sort('timestamp', -1).limit(5))
    return render_template('index.html', stats=dashboard_stats, recent_lookups=recent_lookups)

# Threat lookup route
@app.route('/lookup', methods=['GET', 'POST'])
def threat_lookup():
    if request.method == 'POST':
        indicator = request.form.get('indicator')
        if not indicator:
            return render_template('lookup.html', error="Please enter an indicator")
        
        # Query APIs
        results = query_threat_apis(indicator)
        
        # Save to MongoDB
        for result in results:
            result['timestamp'] = datetime.now()
            result['indicator'] = indicator
            mongo.db.threat_lookups.insert_one(result)
        
        # Get tags for this indicator
        tags = get_tags_for_indicator(indicator)
        
        # Update dashboard stats
        update_dashboard_stats()
        
        return render_template('lookup.html', results=results, indicator=indicator, 
                              tags=tags, stats=dashboard_stats)
    
    return render_template('lookup.html', stats=dashboard_stats)

# Query threat intelligence APIs
def query_threat_apis(indicator):
    results = []
    
    # VirusTotal API
    try:
        vt_url = f"https://www.virustotal.com/api/v3/search?query={indicator}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(vt_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and len(data['data']) > 0:
                item = data['data'][0]
                attributes = item.get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                malicious = last_analysis_stats.get('malicious', 0)
                
                threat_level = "Low"
                if malicious > 5:
                    threat_level = "High"
                elif malicious > 0:
                    threat_level = "Medium"
                
                results.append({
                    "indicator": indicator,
                    "threat_level": threat_level,
                    "source": "VirusTotal",
                    "details": f"Malicious detections: {malicious}",
                    "severity_score": malicious
                })
    except Exception as e:
        print(f"VirusTotal API error: {e}")
    
    # AbuseIPDB API
    try:
        if '.' in indicator and not any(c.isalpha() for c in indicator):  # Likely an IP address
            abuse_url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            params = {'ipAddress': indicator, 'maxAgeInDays': 90}
            response = requests.get(abuse_url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                abuse_confidence = data['data'].get('abuseConfidenceScore', 0)
                total_reports = data['data'].get('totalReports', 0)
                
                threat_level = "Low"
                if abuse_confidence > 85:
                    threat_level = "High"
                elif abuse_confidence > 50:
                    threat_level = "Medium"
                
                results.append({
                    "indicator": indicator,
                    "threat_level": threat_level,
                    "source": "AbuseIPDB",
                    "details": f"Abuse confidence: {abuse_confidence}%, Reports: {total_reports}",
                    "severity_score": abuse_confidence
                })
    except Exception as e:
        print(f"AbuseIPDB API error: {e}")
    
    # AlienVault OTX API
    try:
        indicator_type = "domain"
        if '.' in indicator and not any(c.isalpha() for c in indicator.split('.')[-1]):
            indicator_type = "IPv4"
        elif len(indicator) in [32, 40, 64]:  # MD5, SHA1, SHA256 hashes
            indicator_type = "file"
            
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
        headers = {'X-OTX-API-KEY': ALIENVAULT_API_KEY}
        response = requests.get(otx_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            pulse_info = data.get('pulse_info', {})
            count = pulse_info.get('count', 0)
            
            threat_level = "Low"
            if count > 5:
                threat_level = "High"
            elif count > 0:
                threat_level = "Medium"
            
            results.append({
                "indicator": indicator,
                "threat_level": threat_level,
                "source": "AlienVault OTX",
                "details": f"Found in {count} threat pulses",
                "severity_score": count
            })
    except Exception as e:
        print(f"AlienVault API error: {e}")
    
    return results

# Trends and visualization route
@app.route('/trends')
def trends():
    # Get data for charts
    lookups = list(mongo.db.threat_lookups.find())
    
    # Prepare data for charts
    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    daily_counts = {}
    top_indicators = {}
    
    for lookup in lookups:
        # Count severity levels
        severity = lookup.get('threat_level', 'Low')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count daily lookups
        date_str = lookup['timestamp'].strftime("%Y-%m-%d")
        daily_counts[date_str] = daily_counts.get(date_str, 0) + 1
        
        # Count top indicators
        indicator = lookup.get('indicator', '')
        if indicator:
            top_indicators[indicator] = top_indicators.get(indicator, 0) + 1
    
    # Sort and get top 10 indicators
    top_indicators = dict(sorted(top_indicators.items(), key=lambda x: x[1], reverse=True)[:10])
    
    return render_template('trends.html', 
                         severity_counts=severity_counts,
                         daily_counts=daily_counts,
                         top_indicators=top_indicators,
                         stats=dashboard_stats)

# Export route
@app.route('/export')
def export_data():
    format_type = request.args.get('format', 'csv')
    lookups = list(mongo.db.threat_lookups.find())
    
    if format_type == 'csv':
        # Create CSV
        si = StringIO()
        cw = csv.writer(si)
        cw.writerow(['Indicator', 'Threat Level', 'Source', 'Details', 'Timestamp'])
        
        for lookup in lookups:
            cw.writerow([
                lookup.get('indicator', ''),
                lookup.get('threat_level', ''),
                lookup.get('source', ''),
                lookup.get('details', ''),
                lookup.get('timestamp', '').strftime("%Y-%m-%d %H:%M:%S")
            ])
        
        output = si.getvalue()
        return send_file(
            BytesIO(output.encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name='threat_intel_export.csv'
        )
    
    elif format_type == 'pdf':
        # Create PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        
        # Add title
        styles = getSampleStyleSheet()
        title = Paragraph("Threat Intelligence Report", styles['Title'])
        elements.append(title)
        
        # Add table
        data = [['Indicator', 'Threat Level', 'Source', 'Details', 'Timestamp']]
        
        for lookup in lookups:
            data.append([
                lookup.get('indicator', ''),
                lookup.get('threat_level', ''),
                lookup.get('source', ''),
                lookup.get('details', ''),
                lookup.get('timestamp', '').strftime("%Y-%m-%d %H:%M:%S")
            ])
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(table)
        doc.build(elements)
        
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name='threat_intel_report.pdf'
        )
    
    return "Invalid format specified", 400

# Export page route
@app.route('/export-page')
def export_page():
    # Get recent lookups for the display
    recent_lookups = list(mongo.db.threat_lookups.find().sort('timestamp', -1).limit(10))
    return render_template('export.html', recent_lookups=recent_lookups, stats=dashboard_stats)

# API endpoint to add tags
@app.route('/add_tag', methods=['POST'])
def add_tag():
    data = request.json
    indicator = data.get('indicator')
    tag = data.get('tag')
    
    if not indicator or not tag:
        return jsonify({'error': 'Indicator and tag are required'}), 400
    
    mongo.db.threat_lookups.update_many(
        {'indicator': indicator},
        {'$addToSet': {'tags': tag}}
    )
    
    return jsonify({'success': True})

# API endpoint to get tags
@app.route('/get_tags/<indicator>')
def get_tags(indicator):
    tags = get_tags_for_indicator(indicator)
    return jsonify({'tags': tags})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
