#!/usr/bin/env python3
"""
Advanced Flask Frontend for AI Code Review Dashboard
Fixed version with proper imports and error handling
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, make_response, Response
from flask_socketio import SocketIO, emit, join_room, leave_room
import requests
import json
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
from functools import wraps

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import config with fallback
try:
    from config import Config
    SECRET_KEY = getattr(Config, 'SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = getattr(Config, 'DEBUG', True)
except ImportError:
    SECRET_KEY = 'dev-secret-key-change-in-production'
    DEBUG = True

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize SocketIO for real-time features
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# API Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000/api")

class APIClient:
    """Client for making requests to the backend API."""
    
    @staticmethod
    def make_request(endpoint: str, method: str = 'GET', data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict:
        try:
            url = f"{API_BASE_URL}{endpoint}"
            
            # Set longer timeout for repository operations
            timeout = 60 if 'repositories' in endpoint else 30
            
            if method == 'GET':
                # Use params for GET requests, data for others
                request_params = params or data
                response = requests.get(url, params=request_params, timeout=timeout)
            else: # POST, PUT, DELETE
                response = requests.request(method, url, json=data, timeout=timeout)
            
            if 200 <= response.status_code < 300:
                try:
                    return response.json()
                except json.JSONDecodeError:
                    return {"status": "success", "message": "Action completed."}
            else:
                logger.error(f"API Error {response.status_code}: {response.text}")
                return {"error": f"API Error: {response.status_code}", "detail": response.text}
        except requests.exceptions.Timeout:
            logger.error(f"API request timeout for {endpoint}")
            if 'repositories' in endpoint:
                return {"error": "Repository fetch timeout", "detail": "GitHub/GitLab API is taking too long. Please try again later."}
            return {"error": "Request timeout", "detail": "The backend service is taking too long to respond"}
        except requests.exceptions.ConnectionError:
            logger.error(f"API connection error for {endpoint}")
            return {"error": "Connection failed", "detail": "Cannot connect to backend service. Please ensure the backend is running."}
        except requests.RequestException as e:
            logger.error(f"API request failed for {endpoint}: {e}")
            return {"error": "Service connection failed", "detail": str(e)}

# Get analytics data for templates
def get_analytics_data():
    """Get analytics data for templates, with fallback if backend fails."""
    try:
        analytics = APIClient.make_request('/analytics/dashboard')
        if 'error' in analytics:
            raise Exception(f"Backend error: {analytics.get('error')}")
        return analytics
    except Exception as e:
        logger.warning(f"Using fallback analytics data: {e}")
        return {
            'reviews': {'total': 0, 'average_score': 0},
            'issues': {
                'total': 0,
                'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            }
        }

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # For API endpoints, return JSON error instead of redirect
            if request.path.startswith('/api/'):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Main Routes ---

@app.route('/')
@login_required
def index():
    """Main dashboard page"""
    analytics = get_analytics_data()
    return render_template('dashboard.html', analytics=analytics, user=session.get('user'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'admin123':
            session['user_id'] = 1
            session['user'] = {'id': 1, 'username': 'admin', 'full_name': 'System Administrator'}
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials!', 'error')
    return render_template('login.html', user=None)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/repositories')
@login_required
def repositories():
    analytics = get_analytics_data()
    return render_template('repositories.html', analytics=analytics, user=session.get('user'))

@app.route('/code-analysis')
@login_required
def code_analysis():
    analytics = get_analytics_data()
    return render_template('code_analysis.html', analytics=analytics, user=session.get('user'))

@app.route('/ai-assistant')
@login_required
def ai_assistant():
    analytics = get_analytics_data()
    return render_template('ai_assistant.html', analytics=analytics, user=session.get('user'))

@app.route('/analytics')
@login_required
def analytics():
    """Display the analytics dashboard page."""
    analytics = get_analytics_data()
    return render_template('analytics.html', analytics=analytics, user=session.get('user'))

@app.route('/settings')
@login_required
def settings():
    """Display the settings page."""
    analytics = get_analytics_data()
    return render_template('settings.html', analytics=analytics, user=session.get('user'))

@app.route('/reviews')
@login_required
def reviews():
    """Display a history of all code reviews."""
    analytics = get_analytics_data()
    all_reviews = APIClient.make_request('/reviews')
    # Convert string dates to datetime objects for template formatting
    for review in all_reviews:
        if review.get('created_at'):
            review['created_at'] = datetime.fromisoformat(review['created_at'])
    return render_template('reviews.html', analytics=analytics, reviews=all_reviews, user=session.get('user'))

@app.route('/reviews/<int:review_id>')
@login_required
def review_details(review_id):
    """Display the detailed report for a specific code review."""
    analytics = get_analytics_data()
    review_data = APIClient.make_request(f'/reviews/{review_id}')
    if 'error' in review_data:
        flash(review_data.get('detail', 'Could not load review details.'), 'danger')
        return redirect(url_for('reviews'))
    return render_template('review_details.html', analytics=analytics, review=review_data['review'], issues=review_data['issues'], user=session.get('user'))

@app.route('/enterprise')
@login_required
def enterprise_dashboard():
    """Enterprise dashboard with all advanced features"""
    analytics = get_analytics_data()
    return render_template('enterprise_simple.html', analytics=analytics, user=session.get('user'))

@app.route('/enterprise-test')
def enterprise_test():
    """Test enterprise dashboard without login requirement"""
    return """
    <h1>Enterprise Test Page</h1>
    <p>If you can see this, the route is working!</p>
    <p><a href="/enterprise">Try Enterprise Dashboard (requires login)</a></p>
    <p><a href="/">Back to Main Page</a></p>
    """

@app.route('/pr-review')
@login_required
def pr_review():
    analytics = get_analytics_data()
    return render_template('pr_review.html', analytics=analytics, user=session.get('user'))

@app.route('/compliance')
@login_required
def compliance():
    analytics = get_analytics_data()
    return render_template('compliance.html', analytics=analytics, user=session.get('user'))

# --- API Routes for Frontend AJAX Calls ---

@app.route('/api/repositories/list', methods=['GET'])
@login_required
def list_repositories():
    """Fetch repositories from the backend."""
    platform = request.args.get('platform', 'github')
    repos = APIClient.make_request('/repositories', method='GET', params={'platform': platform})
    return jsonify(repos)

@app.route('/api/repositories', methods=['GET'])
@login_required
def get_repositories():
    """Fetch repositories from the backend (alternative endpoint)."""
    platform = request.args.get('platform', 'github')
    repos = APIClient.make_request('/repositories', method='GET', params={'platform': platform})
    return jsonify(repos)

@app.route('/api/analyze/repository', methods=['POST'])
@login_required
def analyze_repository():
    """Trigger a repository analysis."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON in request"}), 400
    repo_id = data.get('repo_id')
    if not repo_id:
        return jsonify({"error": "repo_id is required"}), 400
    
    result = APIClient.make_request(f'/analyze/repository/{repo_id}', method='POST')
    return jsonify(result)

@app.route('/api/analyze/repository/<int:repo_id>', methods=['POST'])
@login_required
def analyze_repository_by_id(repo_id):
    """Trigger a repository analysis by ID."""
    result = APIClient.make_request(f'/analyze/repository/{repo_id}', method='POST')
    return jsonify(result)

@app.route('/api/analyze/file', methods=['POST'])
@login_required
def analyze_file():
    """Analyze a single file."""
    result = APIClient.make_request('/analyze/file', method='POST', data=request.json)
    return jsonify(result)

@app.route('/api/reviews/<int:review_id>/status', methods=['GET'])
@login_required
def get_review_status(review_id):
    """Get the status of a specific review."""
    result = APIClient.make_request(f'/reviews/{review_id}/status')
    return jsonify(result)

@app.route('/api/reviews/<int:review_id>', methods=['GET'])
@login_required
def get_review_details_api(review_id):
    """Get detailed results for a specific review via API."""
    result = APIClient.make_request(f'/reviews/{review_id}')
    return jsonify(result)

@app.route('/api/reviews/<int:review_id>/download', methods=['GET'])
@login_required
def download_review_report(review_id):
    """Proxy download request to backend and return the HTML file."""
    try:
        # Make request to backend
        backend_url = f"http://localhost:8000/api/reviews/{review_id}/download"
        response = requests.get(backend_url, timeout=30)
        
        if response.status_code == 200:
            # Return the HTML content with proper headers for download
            return Response(
                response.content,
                mimetype='text/html',
                headers={
                    'Content-Disposition': f'attachment; filename=code_review_{review_id}.html'
                }
            )
        else:
            return jsonify({"error": f"Backend returned {response.status_code}"}), response.status_code
            
    except Exception as e:
        logger.error(f"Download proxy error: {e}")
        return jsonify({"error": f"Download failed: {str(e)}"}), 500

# GitHub Settings API Proxy Endpoints
@app.route('/api/settings/github', methods=['GET'])
@login_required
def get_github_settings():
    """Get GitHub settings - proxy to backend."""
    result = APIClient.make_request('/settings/github', method='GET')
    return jsonify(result)

@app.route('/api/settings/github', methods=['POST'])
@login_required
def save_github_settings():
    """Save GitHub settings - proxy to backend."""
    result = APIClient.make_request('/settings/github', method='POST', data=request.json)
    return jsonify(result)

@app.route('/api/settings/github/test', methods=['POST'])
@login_required
def test_github_connection():
    """Test GitHub connection - proxy to backend."""
    result = APIClient.make_request('/settings/github/test', method='POST', data=request.json)
    return jsonify(result)

@app.route('/api/settings/github', methods=['DELETE'])
@login_required
def clear_github_settings():
    """Clear GitHub settings - proxy to backend."""
    result = APIClient.make_request('/settings/github', method='DELETE')
    return jsonify(result)

@app.route('/api/ai-assistant/chat', methods=['POST'])
@login_required
def ai_chat():
    """Handle AI assistant chat requests."""
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({"error": "Message is required"}), 400
        
        result = APIClient.make_request('/ai-assistant/chat', method='POST', data=data)
        return jsonify(result)
    except Exception as e:
        logger.error(f"AI chat error: {e}")
        return jsonify({"error": "Failed to process chat request", "detail": str(e)}), 500

@app.route('/api/analytics/dashboard', methods=['GET'])
@login_required
def analytics_dashboard_api():
    """Get dashboard analytics data."""
    result = APIClient.make_request('/analytics/dashboard')
    return jsonify(result)

@app.route('/api/test-login', methods=['POST'])
def test_login():
    """Simple API login for testing."""
    data = request.get_json() or {}
    username = data.get('username', 'demo')
    password = data.get('password', 'demo')
    
    if username == 'demo' and password == 'demo':
        session['user_id'] = 1
        session['user'] = {'id': 1, 'username': 'demo', 'name': 'Demo User'}
        return jsonify({"status": "success", "message": "Logged in successfully"})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/compliance/report', methods=['GET'])
@login_required
def proxy_compliance_report():
    result = APIClient.make_request('/compliance/report', method='GET')
    return jsonify(result)

@app.route('/api/pr/analyze', methods=['POST'])
@login_required
def proxy_pr_analyze():
    platform = request.args.get('platform', 'github')
    # Build endpoint with platform query param
    endpoint = f'/pr/analyze?platform={platform}'
    result = APIClient.make_request(endpoint, method='POST', data=request.json)
    return jsonify(result)

@app.route('/api/autofix/analyze', methods=['POST'])
@login_required
def proxy_autofix_analyze():
    result = APIClient.make_request('/autofix/analyze', method='POST', data=request.json)
    return jsonify(result)

# --- WebSocket Events ---

@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        return False
    emit('status', {'message': 'Connected to the AI Code Review frontend server.'})
    logger.info(f"Client connected: {getattr(request, 'sid', 'N/A')}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {getattr(request, 'sid', 'N/A')}")

@socketio.on('ai_chat_message')
def handle_ai_chat(data):
    message = data.get('message', '')
    # Placeholder for real AI chat logic
    ai_response = f"AI thinking about: '{message}'... (feature coming soon)"
    emit('ai_chat_response', {'message': ai_response})

# --- Error Handlers ---
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    logger.info("Starting Flask app directly...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=DEBUG, allow_unsafe_werkzeug=True) 