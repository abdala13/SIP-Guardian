from flask import Flask, render_template, request, jsonify
from scanner import SIPAuditEngine
import os

app = Flask(__name__)
logs = []
engine = None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/start', methods=['POST'])
def start():
    global engine, logs
    logs = []
    data = request.json
    target = data.get('target')
    username = data.get('username')
    passwords = data.get('passwords', '').split(',')
    
    engine = SIPAuditEngine(target, 5060, username, passwords, lambda m: logs.append(m))
    engine.start()
    return jsonify({"status": "running"})

@app.route('/api/logs')
def get_logs():
    return jsonify({"logs": logs})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
