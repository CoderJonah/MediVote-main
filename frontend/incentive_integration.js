/**
 * MediVote Node Incentive Integration
 * Frontend integration for the node incentive system
 * 
 * Users can only create ballots if they're running a node,
 * with real-time verification and status updates.
 */

class NodeIncentiveIntegration {
    constructor() {
        this.incentiveApiUrl = 'http://localhost:8082';
        this.backendApiUrl = 'http://localhost:8001';
        this.nodeId = null;
        this.nodeStatus = null;
        this.isConnected = false;
        
        // Initialize the integration
        this.init();
    }
    
    async init() {
        console.log('🌐 Initializing Node Incentive Integration...');
        
        // Check if user has a registered node
        await this.checkNodeRegistration();
        
        // Set up UI elements
        this.setupUI();
        
        // Start periodic status updates
        this.startStatusUpdates();
    }
    
    setupUI() {
        // Create incentive status panel
        const incentivePanel = document.createElement('div');
        incentivePanel.id = 'incentive-panel';
        incentivePanel.className = 'incentive-panel';
        incentivePanel.innerHTML = `
            <div class="incentive-header">
                <h3>🎁 Node Incentive System</h3>
                <p>Run a node to create ballots</p>
            </div>
            <div class="incentive-status" id="incentive-status">
                <div class="status-loading">Checking node status...</div>
            </div>
            <div class="incentive-actions" id="incentive-actions">
                <button id="register-node-btn" class="btn btn-primary" style="display: none;">
                    🚀 Register Your Node
                </button>
                <button id="check-status-btn" class="btn btn-secondary" style="display: none;">
                    🔄 Check Status
                </button>
                <button id="create-ballot-btn" class="btn btn-success" style="display: none;">
                    🗳️ Create Ballot
                </button>
            </div>
        `;
        
        // Add styles
        const styles = document.createElement('style');
        styles.textContent = `
            .incentive-panel {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            
            .incentive-header h3 {
                margin: 0 0 5px 0;
                font-size: 1.2em;
            }
            
            .incentive-header p {
                margin: 0 0 15px 0;
                opacity: 0.9;
            }
            
            .incentive-status {
                margin: 15px 0;
                padding: 15px;
                background: rgba(255,255,255,0.1);
                border-radius: 5px;
            }
            
            .status-loading {
                text-align: center;
                font-style: italic;
            }
            
            .status-success {
                color: #28a745;
                font-weight: bold;
            }
            
            .status-error {
                color: #dc3545;
                font-weight: bold;
            }
            
            .status-warning {
                color: #ffc107;
                font-weight: bold;
            }
            
            .node-info {
                margin: 10px 0;
                padding: 10px;
                background: rgba(255,255,255,0.05);
                border-radius: 3px;
                font-size: 0.9em;
            }
            
            .incentive-actions {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
            }
            
            .btn {
                padding: 8px 16px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 0.9em;
                transition: all 0.3s ease;
            }
            
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            }
            
            .btn-primary {
                background: #007bff;
                color: white;
            }
            
            .btn-secondary {
                background: #6c757d;
                color: white;
            }
            
            .btn-success {
                background: #28a745;
                color: white;
            }
            
            .btn:disabled {
                opacity: 0.6;
                cursor: not-allowed;
                transform: none;
            }
            
            .ballot-form {
                margin-top: 15px;
                padding: 15px;
                background: rgba(255,255,255,0.05);
                border-radius: 5px;
                display: none;
            }
            
            .ballot-form input,
            .ballot-form textarea {
                width: 100%;
                padding: 8px;
                margin: 5px 0;
                border: none;
                border-radius: 3px;
                background: rgba(255,255,255,0.9);
                color: #333;
            }
            
            .ballot-form label {
                display: block;
                margin-top: 10px;
                font-weight: bold;
            }
        `;
        
        document.head.appendChild(styles);
        
        // Insert the panel into the page
        const container = document.querySelector('.container') || document.body;
        container.insertBefore(incentivePanel, container.firstChild);
        
        // Set up event listeners
        this.setupEventListeners();
    }
    
    setupEventListeners() {
        // Register node button
        const registerBtn = document.getElementById('register-node-btn');
        if (registerBtn) {
            registerBtn.addEventListener('click', () => this.registerNode());
        }
        
        // Check status button
        const checkBtn = document.getElementById('check-status-btn');
        if (checkBtn) {
            checkBtn.addEventListener('click', () => this.checkNodeStatus());
        }
        
        // Create ballot button
        const createBtn = document.getElementById('create-ballot-btn');
        if (createBtn) {
            createBtn.addEventListener('click', () => this.showBallotForm());
        }
    }
    
    async checkNodeRegistration() {
        try {
            // Check if user has a stored node ID
            this.nodeId = localStorage.getItem('medivote_node_id');
            
            if (this.nodeId) {
                console.log('Found stored node ID:', this.nodeId);
                await this.checkNodeStatus();
            } else {
                console.log('No registered node found');
                this.showRegistrationPrompt();
            }
        } catch (error) {
            console.error('Error checking node registration:', error);
            this.showError('Failed to check node registration');
        }
    }
    
    async checkNodeStatus() {
        if (!this.nodeId) {
            this.showError('No node registered');
            return;
        }
        
        try {
            const response = await fetch(`${this.incentiveApiUrl}/api/node-status/${this.nodeId}`);
            const data = await response.json();
            
            if (response.ok) {
                this.nodeStatus = data;
                this.updateStatusDisplay(data);
            } else {
                this.showError(data.error || 'Failed to check node status');
            }
        } catch (error) {
            console.error('Error checking node status:', error);
            this.showError('Failed to connect to incentive system');
        }
    }
    
    updateStatusDisplay(status) {
        const statusElement = document.getElementById('incentive-status');
        const registerBtn = document.getElementById('register-node-btn');
        const checkBtn = document.getElementById('check-status-btn');
        const createBtn = document.getElementById('create-ballot-btn');
        
        if (!statusElement) return;
        
        let statusHtml = '';
        let showRegister = false;
        let showCheck = true;
        let showCreate = false;
        
        if (status.is_registered) {
            statusHtml += `<div class="status-success">✅ Node Registered</div>`;
            statusHtml += `<div class="node-info">`;
            statusHtml += `<strong>Node ID:</strong> ${status.node_id}<br>`;
            statusHtml += `<strong>Uptime:</strong> ${status.uptime_hours.toFixed(1)} hours<br>`;
            statusHtml += `<strong>Reputation:</strong> ${status.reputation_score.toFixed(1)}<br>`;
            statusHtml += `<strong>Ballots Created:</strong> ${status.ballot_count}<br>`;
            statusHtml += `<strong>Ballots Remaining:</strong> ${status.ballots_remaining}<br>`;
            statusHtml += `</div>`;
            
            if (status.is_currently_running) {
                statusHtml += `<div class="status-success">🟢 Node is Running</div>`;
                
                if (status.meets_requirements) {
                    statusHtml += `<div class="status-success">✅ Eligible to Create Ballots</div>`;
                    showCreate = true;
                } else {
                    statusHtml += `<div class="status-warning">⚠️ Requirements not met</div>`;
                }
            } else {
                statusHtml += `<div class="status-error">🔴 Node is Offline</div>`;
                statusHtml += `<div class="status-warning">Start your node to create ballots</div>`;
            }
        } else {
            statusHtml += `<div class="status-error">❌ No Node Registered</div>`;
            statusHtml += `<div class="status-warning">Register a node to create ballots</div>`;
            showRegister = true;
        }
        
        statusElement.innerHTML = statusHtml;
        
        // Show/hide buttons
        if (registerBtn) registerBtn.style.display = showRegister ? 'block' : 'none';
        if (checkBtn) checkBtn.style.display = showCheck ? 'block' : 'none';
        if (createBtn) createBtn.style.display = showCreate ? 'block' : 'none';
    }
    
    showRegistrationPrompt() {
        const statusElement = document.getElementById('incentive-status');
        const registerBtn = document.getElementById('register-node-btn');
        
        if (statusElement) {
            statusElement.innerHTML = `
                <div class="status-warning">⚠️ No Node Registered</div>
                <div class="node-info">
                    To create ballots, you need to run a MediVote node.<br>
                    Click "Register Your Node" to get started.
                </div>
            `;
        }
        
        if (registerBtn) {
            registerBtn.style.display = 'block';
        }
    }
    
    showError(message) {
        const statusElement = document.getElementById('incentive-status');
        if (statusElement) {
            statusElement.innerHTML = `<div class="status-error">❌ ${message}</div>`;
        }
    }
    
    async registerNode() {
        try {
            // Generate a unique node ID
            const nodeId = `node_${Math.random().toString(36).substr(2, 9)}`;
            const publicKey = `pk_${Math.random().toString(36).substr(2, 16)}`;
            
            // For demo purposes, assume node is running on localhost
            const nodeAddress = 'localhost';
            const nodePort = 8545;
            
            const response = await fetch(`${this.incentiveApiUrl}/api/register-node`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    node_id: nodeId,
                    public_key: publicKey,
                    node_address: nodeAddress,
                    node_port: nodePort
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.nodeId = nodeId;
                localStorage.setItem('medivote_node_id', nodeId);
                
                console.log('Node registered successfully:', data);
                this.showSuccess('Node registered successfully!');
                
                // Check status after registration
                await this.checkNodeStatus();
            } else {
                this.showError(data.error || 'Failed to register node');
            }
        } catch (error) {
            console.error('Error registering node:', error);
            this.showError('Failed to register node');
        }
    }
    
    showBallotForm() {
        // Create ballot form
        const ballotForm = document.createElement('div');
        ballotForm.className = 'ballot-form';
        ballotForm.id = 'ballot-form';
        ballotForm.innerHTML = `
            <h4>🗳️ Create New Ballot</h4>
            <form id="ballot-creation-form">
                <label for="ballot-title">Ballot Title:</label>
                <input type="text" id="ballot-title" name="title" required placeholder="Enter ballot title">
                
                <label for="ballot-description">Description:</label>
                <textarea id="ballot-description" name="description" rows="3" placeholder="Enter ballot description"></textarea>
                
                <label for="ballot-candidates">Candidates (one per line):</label>
                <textarea id="ballot-candidates" name="candidates" rows="4" required placeholder="Candidate 1&#10;Candidate 2&#10;Candidate 3"></textarea>
                
                <label for="ballot-start-date">Start Date:</label>
                <input type="datetime-local" id="ballot-start-date" name="start_date" required>
                
                <label for="ballot-end-date">End Date:</label>
                <input type="datetime-local" id="ballot-end-date" name="end_date" required>
                
                <div style="margin-top: 15px;">
                    <button type="submit" class="btn btn-success">Create Ballot</button>
                    <button type="button" class="btn btn-secondary" onclick="this.parentElement.parentElement.parentElement.remove()">Cancel</button>
                </div>
            </form>
        `;
        
        // Insert form after the incentive panel
        const incentivePanel = document.getElementById('incentive-panel');
        if (incentivePanel) {
            incentivePanel.appendChild(ballotForm);
            ballotForm.style.display = 'block';
        }
        
        // Set up form submission
        const form = document.getElementById('ballot-creation-form');
        if (form) {
            form.addEventListener('submit', (e) => this.handleBallotSubmission(e));
        }
        
        // Set default dates
        const now = new Date();
        const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
        const nextWeek = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
        
        const startDateInput = document.getElementById('ballot-start-date');
        const endDateInput = document.getElementById('ballot-end-date');
        
        if (startDateInput) {
            startDateInput.value = tomorrow.toISOString().slice(0, 16);
        }
        if (endDateInput) {
            endDateInput.value = nextWeek.toISOString().slice(0, 16);
        }
    }
    
    async handleBallotSubmission(event) {
        event.preventDefault();
        
        if (!this.nodeId) {
            this.showError('No node registered');
            return;
        }
        
        try {
            const formData = new FormData(event.target);
            const ballotData = {
                title: formData.get('title'),
                description: formData.get('description'),
                candidates: formData.get('candidates').split('\n').filter(c => c.trim()),
                start_date: formData.get('start_date'),
                end_date: formData.get('end_date')
            };
            
            const response = await fetch(`${this.incentiveApiUrl}/api/request-ballot`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    node_id: this.nodeId,
                    ballot_data: ballotData
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.showSuccess('Ballot request created successfully!');
                console.log('Ballot request created:', data);
                
                // Remove the form
                const form = document.getElementById('ballot-form');
                if (form) form.remove();
                
                // Update status
                await this.checkNodeStatus();
            } else {
                this.showError(data.error || 'Failed to create ballot request');
                if (data.requirements) {
                    console.log('Requirements not met:', data.requirements);
                }
            }
        } catch (error) {
            console.error('Error creating ballot:', error);
            this.showError('Failed to create ballot');
        }
    }
    
    showSuccess(message) {
        const statusElement = document.getElementById('incentive-status');
        if (statusElement) {
            const successDiv = document.createElement('div');
            successDiv.className = 'status-success';
            successDiv.textContent = `✅ ${message}`;
            statusElement.appendChild(successDiv);
            
            // Remove success message after 5 seconds
            setTimeout(() => {
                successDiv.remove();
            }, 5000);
        }
    }
    
    startStatusUpdates() {
        // Update status every 30 seconds
        setInterval(() => {
            if (this.nodeId) {
                this.checkNodeStatus();
            }
        }, 30000);
    }
}

// Initialize the incentive integration when the page loads
document.addEventListener('DOMContentLoaded', () => {
    window.nodeIncentive = new NodeIncentiveIntegration();
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = NodeIncentiveIntegration;
} 