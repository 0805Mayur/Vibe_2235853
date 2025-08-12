#!/usr/bin/env python3
"""
Simple Working Version - AI Code Review Dashboard
Starts both servers with minimal complexity
"""

import os
import sys
import threading
import time

def run_backend():
    """Run backend server"""
    print("Starting backend...")
    os.system("python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --log-level warning")

def run_frontend():
    """Run frontend server"""
    print("Starting frontend...")
    time.sleep(5)  # Wait for backend
    
    # Import and run frontend
    sys.path.append('.')
    from frontend.app import app
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)

def main():
    print("="*60)
    print("AI Code Review Dashboard - Working Version")
    print("="*60)
    print("Frontend: http://127.0.0.1:5000")
    print("Backend:  http://127.0.0.1:8000")
    print("API Docs: http://127.0.0.1:8000/docs")
    print("="*60)
    
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    # Start backend in thread
    backend_thread = threading.Thread(target=run_backend, daemon=True)
    backend_thread.start()
    
    # Start frontend (blocks)
    try:
        run_frontend()
    except KeyboardInterrupt:
        print("\nShutting down...")

if __name__ == "__main__":
    main() 