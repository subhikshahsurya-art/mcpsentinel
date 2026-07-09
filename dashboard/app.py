from flask import Flask, jsonify, render_template
import json
import os
import subprocess

app = Flask(__name__, template_folder='templates')

RESULTS_FILE = "/home/subhikshah/MCPSentinel/scanner/scan_results.json"

@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/api/results')
def results():
    try:
        with open(RESULTS_FILE) as f:
            return jsonify(json.load(f))
    except:
        return jsonify([])

@app.route('/api/scan')
def run_scan():
    subprocess.run(['python3', '/home/subhikshah/MCPSentinel/scanner/mcp_scanner.py'])
    try:
        with open(RESULTS_FILE) as f:
            return jsonify(json.load(f))
    except:
        return jsonify([])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
