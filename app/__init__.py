from datetime import datetime
from flask import Flask, render_template, request, jsonify

from app.detector import SecurityDetector
from app.samples import SAMPLES, get_sample_by_id

app = Flask(__name__, template_folder='templates', static_folder='static')
detector = SecurityDetector()

# In-memory session audit log
audit_history = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.get_json(silent=True) or {}
    content = data.get('content', '')
    
    result = detector.analyze(content)
    
    return jsonify(result)

@app.route('/api/samples', methods=['GET'])
def api_samples():
    return jsonify(SAMPLES)

@app.route('/api/samples/<sample_id>', methods=['GET'])
def api_sample_detail(sample_id):
    sample = get_sample_by_id(sample_id)
    if not sample:
        return jsonify({"error": "Sample not found"}), 404
    return jsonify(sample)

@app.route('/api/action', methods=['POST'])
def api_action():
    data = request.get_json(silent=True) or {}
    action = data.get('action', 'UNKNOWN')
    risk_level = data.get('risk_level', 'SAFE')
    risk_score = data.get('risk_score', 0)
    snippet_preview = data.get('snippet_preview', 'No content')[:60]
    
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "preview": snippet_preview
    }
    
    audit_history.insert(0, entry)
    
    return jsonify({
        "status": "success",
        "message": f"Action '{action}' recorded successfully.",
        "history": audit_history[:10]
    })

@app.route('/api/history', methods=['GET'])
def api_history():
    return jsonify(audit_history[:10])
