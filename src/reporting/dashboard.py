"""
Dashboard Module for AI-ADMS

This module provides a web-based dashboard for real-time monitoring
of the AI-ADMS system.
"""

import json
import time
import threading
from typing import Dict, List, Optional
import logging
from datetime import datetime

try:
    from flask import Flask, render_template, jsonify, request
    from flask_cors import CORS
except ImportError:
    print("Warning: Flask not available. Install with: pip install flask flask-cors")
    Flask = None


class Dashboard:
    """
    Web dashboard for AI-ADMS system monitoring
    
    This class provides a Flask-based web interface for real-time
    monitoring of system performance and statistics.
    """
    
    def __init__(self, 
                 host: str = "localhost",
                 port: int = 8080,
                 refresh_rate: int = 5):
        """
        Initialize the dashboard
        
        Args:
            host: Dashboard host address
            port: Dashboard port
            refresh_rate: Refresh rate in seconds
        """
        self.host = host
        self.port = port
        self.refresh_rate = refresh_rate
        
        # Flask app
        self.app = None
        self.is_running = False
        
        # System reference (will be set by main system)
        self.system = None
        
        # Logging
        self.logger = logging.getLogger(__name__)
        
        # Initialize Flask app
        self._setup_flask_app()
    
    def _setup_flask_app(self) -> None:
        """Setup Flask application"""
        if Flask is None:
            self.logger.error("Flask not available. Dashboard disabled.")
            return
        
        self.app = Flask(__name__)
        CORS(self.app)
        
        # Setup routes
        self._setup_routes()
    
    def _setup_routes(self) -> None:
        """Setup Flask routes"""
        if not self.app:
            return
        
        @self.app.route('/')
        def index():
            return self._render_dashboard()
        
        @self.app.route('/api/stats')
        def get_stats():
            return jsonify(self._get_system_stats())
        
        @self.app.route('/api/analysis')
        def get_analysis():
            limit = request.args.get('limit', 100, type=int)
            return jsonify(self._get_analysis_data(limit))
        
        @self.app.route('/api/mitigation')
        def get_mitigation():
            limit = request.args.get('limit', 100, type=int)
            return jsonify(self._get_mitigation_data(limit))
        
        @self.app.route('/api/events')
        def get_events():
            limit = request.args.get('limit', 50, type=int)
            return jsonify(self._get_event_data(limit))
    
    def _render_dashboard(self) -> str:
        """Render dashboard HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI-ADMS Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .recent-activity {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .activity-item {
            padding: 10px 0;
            border-bottom: 1px solid #eee;
        }
        .activity-item:last-child {
            border-bottom: none;
        }
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 10px;
        }
        .status-running { background-color: #4CAF50; }
        .status-stopped { background-color: #f44336; }
        .status-warning { background-color: #ff9800; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AI-ADMS Dashboard</h1>
            <p>AI-Driven Adaptive DDoS Mitigation System</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="system-status">Loading...</div>
                <div class="stat-label">System Status</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="packets-processed">0</div>
                <div class="stat-label">Packets Processed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="attacks-detected">0</div>
                <div class="stat-label">Attacks Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="mitigations-performed">0</div>
                <div class="stat-label">Mitigations Performed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="detection-rate">0%</div>
                <div class="stat-label">Detection Rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="avg-confidence">0%</div>
                <div class="stat-label">Avg Confidence</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3>Recent Analysis Results</h3>
            <div id="analysis-chart">Loading...</div>
        </div>
        
        <div class="recent-activity">
            <h3>Recent Activity</h3>
            <div id="activity-feed">Loading...</div>
        </div>
    </div>
    
    <script>
        function updateDashboard() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('system-status').textContent = data.system_status;
                    document.getElementById('packets-processed').textContent = data.total_packets_processed;
                    document.getElementById('attacks-detected').textContent = data.total_attacks_detected;
                    document.getElementById('mitigations-performed').textContent = data.total_mitigations_performed;
                    document.getElementById('detection-rate').textContent = (data.attack_detection_rate * 100).toFixed(1) + '%';
                    document.getElementById('avg-confidence').textContent = (data.avg_confidence * 100).toFixed(1) + '%';
                })
                .catch(error => console.error('Error updating stats:', error));
            
            fetch('/api/events?limit=10')
                .then(response => response.json())
                .then(data => {
                    const activityFeed = document.getElementById('activity-feed');
                    activityFeed.innerHTML = data.map(event => `
                        <div class="activity-item">
                            <span class="status-indicator status-${event.event_type.toLowerCase()}"></span>
                            <strong>${event.event_type}</strong>: ${event.message}
                            <br><small>${new Date(event.timestamp).toLocaleString()}</small>
                        </div>
                    `).join('');
                })
                .catch(error => console.error('Error updating events:', error));
        }
        
        // Update dashboard every 5 seconds
        setInterval(updateDashboard, 5000);
        updateDashboard(); // Initial update
    </script>
</body>
</html>
        """
    
    def _get_system_stats(self) -> Dict:
        """Get system statistics for API"""
        if not self.system:
            return {'error': 'System not connected'}
        
        try:
            return self.system.get_system_stats()
        except Exception as e:
            self.logger.error(f"Error getting system stats: {e}")
            return {'error': str(e)}
    
    def _get_analysis_data(self, limit: int) -> List[Dict]:
        """Get analysis data for API"""
        if not self.system or not hasattr(self.system, 'reporter'):
            return []
        
        try:
            return self.system.reporter.get_recent_analysis_results(limit)
        except Exception as e:
            self.logger.error(f"Error getting analysis data: {e}")
            return []
    
    def _get_mitigation_data(self, limit: int) -> List[Dict]:
        """Get mitigation data for API"""
        if not self.system or not hasattr(self.system, 'reporter'):
            return []
        
        try:
            return self.system.reporter.get_recent_mitigation_results(limit)
        except Exception as e:
            self.logger.error(f"Error getting mitigation data: {e}")
            return []
    
    def _get_event_data(self, limit: int) -> List[Dict]:
        """Get event data for API"""
        if not self.system or not hasattr(self.system, 'reporter'):
            return []
        
        try:
            return self.system.reporter.get_recent_system_events(limit)
        except Exception as e:
            self.logger.error(f"Error getting event data: {e}")
            return []
    
    def start(self) -> bool:
        """Start the dashboard"""
        if not self.app:
            self.logger.error("Flask app not available")
            return False
        
        try:
            self.is_running = True
            
            # Start Flask app in a separate thread
            def run_flask():
                self.app.run(host=self.host, port=self.port, debug=False, use_reloader=False)
            
            flask_thread = threading.Thread(target=run_flask, daemon=True)
            flask_thread.start()
            
            self.logger.info(f"Dashboard started at http://{self.host}:{self.port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting dashboard: {e}")
            return False
    
    def stop(self) -> None:
        """Stop the dashboard"""
        self.is_running = False
        self.logger.info("Dashboard stopped")
    
    def set_system_reference(self, system) -> None:
        """Set reference to main system"""
        self.system = system 