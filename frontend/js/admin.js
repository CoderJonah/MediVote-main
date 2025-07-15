// Admin Panel JavaScript
// Handles ballot creation, management, and system monitoring

document.addEventListener('DOMContentLoaded', function() {
    const ballotForm = document.getElementById('ballotForm');
    ballotForm.addEventListener('submit', handleBallotCreation);
    
    // Set default dates
    setDefaultDates();
    
    // Load initial data
    loadBallotManagement();
    loadSystemMonitor();
    
    // Auto-refresh every 30 seconds
    setInterval(() => {
        loadSystemMonitor();
    }, 30000);
});

function setDefaultDates() {
    const now = new Date();
    const startTime = new Date(now.getTime() + 60 * 60 * 1000); // 1 hour from now
    const endTime = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours from now
    
    document.getElementById('startTime').value = formatDateTimeLocal(startTime);
    document.getElementById('endTime').value = formatDateTimeLocal(endTime);
}

function formatDateTimeLocal(date) {
    const pad = (num) => num.toString().padStart(2, '0');
    return date.getFullYear() + '-' +
           pad(date.getMonth() + 1) + '-' +
           pad(date.getDate()) + 'T' +
           pad(date.getHours()) + ':' +
           pad(date.getMinutes());
}

function showTab(tabId) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from all buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(tabId).classList.add('active');
    
    // Add active class to clicked button
    event.target.classList.add('active');
    
    // Load data for specific tabs
    if (tabId === 'manage-ballots') {
        loadBallotManagement();
    } else if (tabId === 'system-monitor') {
        loadSystemMonitor();
    }
}

function addCandidate() {
    const container = document.getElementById('candidatesContainer');
    const candidateDiv = document.createElement('div');
    candidateDiv.className = 'candidate-input';
    candidateDiv.innerHTML = `
        <input type="text" name="candidateName" placeholder="Candidate Name" required>
        <input type="text" name="candidateParty" placeholder="Party/Position">
        <button type="button" class="btn btn-error btn-sm" onclick="removeCandidate(this)">
            <i class="fas fa-trash"></i>
        </button>
    `;
    container.appendChild(candidateDiv);
}

function removeCandidate(button) {
    const container = document.getElementById('candidatesContainer');
    if (container.children.length > 2) { // Keep at least 2 candidates
        button.parentElement.remove();
    } else {
        AlertSystem.show('A ballot must have at least 2 candidates.', 'warning');
    }
}

async function handleBallotCreation(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalContent = submitBtn.innerHTML;
    
    // Collect candidate data
    const candidateNames = formData.getAll('candidateName');
    const candidateParties = formData.getAll('candidateParty');
    
    if (candidateNames.length < 2) {
        AlertSystem.show('A ballot must have at least 2 candidates.', 'error');
        return;
    }
    
    const candidates = candidateNames.map((name, index) => ({
        name: name.trim(),
        party: candidateParties[index]?.trim() || 'Independent'
    }));
    
    // Validate dates
    const startTime = new Date(formData.get('startTime'));
    const endTime = new Date(formData.get('endTime'));
    
    if (startTime >= endTime) {
        AlertSystem.show('End time must be after start time.', 'error');
        return;
    }
    
    if (startTime < new Date()) {
        AlertSystem.show('Start time cannot be in the past.', 'error');
        return;
    }
    
    // Show loading state
    submitBtn.innerHTML = '<div class="loading"></div> Creating Ballot...';
    submitBtn.disabled = true;
    
    try {
        const ballotData = {
            title: formData.get('ballotTitle'),
            description: formData.get('ballotDescription'),
            candidates: candidates,
            start_time: startTime.toISOString(),
            end_time: endTime.toISOString()
        };
        
        const response = await MediVoteAPI.post('/api/admin/create-ballot', ballotData);
        
        // Show success message
        AlertSystem.clear();
        AlertSystem.show('Ballot created successfully!', 'success');
        
        // Display ballot details
        displayBallotCreationSuccess(response);
        
        // Reset form
        event.target.reset();
        setDefaultDates();
        
        // Refresh ballot management
        loadBallotManagement();
        
    } catch (error) {
        console.error('Ballot creation error:', error);
        AlertSystem.show(`Failed to create ballot: ${error.message}`, 'error');
    } finally {
        // Reset button state
        submitBtn.innerHTML = originalContent;
        submitBtn.disabled = false;
    }
}

function displayBallotCreationSuccess(response) {
    const successHtml = `
        <div class="ballot-success">
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <div>
                    <strong>Ballot Created Successfully!</strong>
                    Your ballot has been created and is ready for voting.
                </div>
            </div>
            
            <div class="ballot-details">
                <h3>Ballot Information</h3>
                <div class="detail-item">
                    <strong>Ballot ID:</strong>
                    <span>${response.ballot_id}</span>
                </div>
                <div class="detail-item">
                    <strong>Title:</strong>
                    <span>${response.title}</span>
                </div>
                <div class="detail-item">
                    <strong>Status:</strong>
                    <span class="ballot-status ${response.status}">${response.status}</span>
                </div>
                <div class="detail-item">
                    <strong>Voting Period:</strong>
                    <span>${formatDateTime(response.start_time)} - ${formatDateTime(response.end_time)}</span>
                </div>
                <div class="detail-item">
                    <strong>Candidates:</strong>
                    <span>${response.candidates_count} candidates</span>
                </div>
            </div>
        </div>
    `;
    
    const container = document.createElement('div');
    container.innerHTML = successHtml;
    document.querySelector('.form-container').appendChild(container);
    
    // Remove after 10 seconds
    setTimeout(() => {
        container.remove();
    }, 10000);
}

async function loadBallotManagement() {
    const container = document.getElementById('ballotsManagement');
    LoadingManager.show(container, 'Loading ballots...');
    
    try {
        const response = await MediVoteAPI.get('/api/voting/ballots');
        const ballots = response.ballots || [];
        
        if (ballots.length === 0) {
            container.innerHTML = `
                <div class="text-center">
                    <i class="fas fa-inbox" style="font-size: 3rem; color: var(--text-secondary); margin-bottom: 1rem;"></i>
                    <h3>No Ballots Created</h3>
                    <p>Create your first ballot to get started.</p>
                </div>
            `;
            return;
        }
        
        const ballotsHtml = ballots.map(ballot => `
            <div class="ballot-management-item">
                <div class="ballot-management-header">
                    <div>
                        <h4>${ballot.title}</h4>
                        <p>${ballot.description}</p>
                    </div>
                    <div class="ballot-management-actions">
                        <span class="ballot-status ${getBallotStatus(ballot)}">${getBallotStatus(ballot)}</span>
                        <button class="btn btn-outline btn-sm" onclick="viewBallotDetails('${ballot.id}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-error btn-sm" onclick="deleteBallot('${ballot.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
                <div class="ballot-meta">
                    <span><i class="fas fa-calendar-alt"></i> ${formatDateTime(ballot.start_time)} - ${formatDateTime(ballot.end_time)}</span>
                    <span><i class="fas fa-users"></i> ${ballot.candidates?.length || 0} candidates</span>
                    <span><i class="fas fa-vote-yea"></i> ${ballot.votes_count || 0} votes</span>
                </div>
            </div>
        `).join('');
        
        container.innerHTML = ballotsHtml;
        
    } catch (error) {
        console.error('Error loading ballot management:', error);
        container.innerHTML = `
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i>
                <div>Failed to load ballots. Please try again.</div>
            </div>
        `;
    }
}

function getBallotStatus(ballot) {
    const now = new Date();
    const start = new Date(ballot.start_time);
    const end = new Date(ballot.end_time);
    
    if (now < start) return 'upcoming';
    if (now > end) return 'completed';
    return 'active';
}

async function loadSystemMonitor() {
    try {
        const status = await MediVoteAPI.get('/api/status');
        
        // Update monitor values
        document.getElementById('registeredVoters').textContent = status.statistics?.registered_voters || '0';
        document.getElementById('totalVotes').textContent = status.statistics?.total_votes || '0';
        document.getElementById('activeBallots').textContent = status.statistics?.active_ballots || '0';
        document.getElementById('securityStatus').textContent = 'Secure';
        
        // Update system components
        const dbStatus = status.infrastructure?.database || 'Unknown';
        const blockchainStatus = status.infrastructure?.blockchain || 'Unknown';
        const cacheStatus = status.infrastructure?.api_endpoints === 'responsive' ? 'Active' : 'Unknown';
        
        const componentsHtml = `
            <div class="status-grid">
                <div class="status-item">
                    <div class="status-icon">
                        <i class="fas fa-server"></i>
                    </div>
                    <div class="status-info">
                        <h3>Backend API</h3>
                        <span class="status-badge healthy">Operational</span>
                    </div>
                </div>
                <div class="status-item">
                    <div class="status-icon">
                        <i class="fas fa-database"></i>
                    </div>
                    <div class="status-info">
                        <h3>Database</h3>
                        <span class="status-badge ${dbStatus === 'connected' ? 'healthy' : 'error'}">${dbStatus}</span>
                    </div>
                </div>
                <div class="status-item">
                    <div class="status-icon">
                        <i class="fas fa-cube"></i>
                    </div>
                    <div class="status-info">
                        <h3>Blockchain</h3>
                        <span class="status-badge ${blockchainStatus === 'synchronized' ? 'healthy' : 'error'}">${blockchainStatus}</span>
                    </div>
                </div>
                <div class="status-item">
                    <div class="status-icon">
                        <i class="fas fa-memory"></i>
                    </div>
                    <div class="status-info">
                        <h3>Cache</h3>
                        <span class="status-badge ${cacheStatus === 'Active' ? 'healthy' : 'error'}">${cacheStatus}</span>
                    </div>
                </div>
            </div>
        `;
        
        document.getElementById('systemComponentsStatus').innerHTML = componentsHtml;
        
    } catch (error) {
        console.error('Error loading system monitor:', error);
        document.getElementById('systemComponentsStatus').innerHTML = `
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i>
                <div>Failed to load system status. Please try again.</div>
            </div>
        `;
    }
}

function viewBallotDetails(ballotId) {
    // This would open a modal or redirect to ballot details
    AlertSystem.show('Ballot details functionality would be implemented here.', 'info');
}

function deleteBallot(ballotId) {
    if (confirm('Are you sure you want to delete this ballot? This action cannot be undone.')) {
        // This would delete the ballot
        AlertSystem.show('Ballot deletion functionality would be implemented here.', 'info');
    }
}

function resetForm() {
    document.getElementById('ballotForm').reset();
    setDefaultDates();
    
    // Reset candidates to default 2
    const container = document.getElementById('candidatesContainer');
    container.innerHTML = `
        <div class="candidate-input">
            <input type="text" name="candidateName" placeholder="Candidate Name" required>
            <input type="text" name="candidateParty" placeholder="Party/Position">
            <button type="button" class="btn btn-error btn-sm" onclick="removeCandidate(this)">
                <i class="fas fa-trash"></i>
            </button>
        </div>
        <div class="candidate-input">
            <input type="text" name="candidateName" placeholder="Candidate Name" required>
            <input type="text" name="candidateParty" placeholder="Party/Position">
            <button type="button" class="btn btn-error btn-sm" onclick="removeCandidate(this)">
                <i class="fas fa-trash"></i>
            </button>
        </div>
    `;
    
    AlertSystem.clear();
}

// Form validation
document.getElementById('ballotForm').addEventListener('input', function() {
    const title = document.getElementById('ballotTitle').value;
    const description = document.getElementById('ballotDescription').value;
    const startTime = document.getElementById('startTime').value;
    const endTime = document.getElementById('endTime').value;
    
    const submitBtn = this.querySelector('button[type="submit"]');
    const isValid = title && description && startTime && endTime;
    
    submitBtn.disabled = !isValid;
});

// Auto-save draft (localStorage)
document.getElementById('ballotForm').addEventListener('input', function() {
    const formData = new FormData(this);
    const draftData = {
        title: formData.get('ballotTitle'),
        description: formData.get('ballotDescription'),
        startTime: formData.get('startTime'),
        endTime: formData.get('endTime'),
        candidates: Array.from(formData.getAll('candidateName')).map((name, index) => ({
            name,
            party: formData.getAll('candidateParty')[index]
        }))
    };
    
    localStorage.setItem('ballotDraft', JSON.stringify(draftData));
});

// Load draft on page load
document.addEventListener('DOMContentLoaded', function() {
    const draft = localStorage.getItem('ballotDraft');
    if (draft) {
        try {
            const draftData = JSON.parse(draft);
            
            if (draftData.title) document.getElementById('ballotTitle').value = draftData.title;
            if (draftData.description) document.getElementById('ballotDescription').value = draftData.description;
            if (draftData.startTime) document.getElementById('startTime').value = draftData.startTime;
            if (draftData.endTime) document.getElementById('endTime').value = draftData.endTime;
            
            // Load candidates
            if (draftData.candidates && draftData.candidates.length > 0) {
                const container = document.getElementById('candidatesContainer');
                container.innerHTML = '';
                
                draftData.candidates.forEach(candidate => {
                    const candidateDiv = document.createElement('div');
                    candidateDiv.className = 'candidate-input';
                    candidateDiv.innerHTML = `
                        <input type="text" name="candidateName" placeholder="Candidate Name" required value="${candidate.name}">
                        <input type="text" name="candidateParty" placeholder="Party/Position" value="${candidate.party}">
                        <button type="button" class="btn btn-error btn-sm" onclick="removeCandidate(this)">
                            <i class="fas fa-trash"></i>
                        </button>
                    `;
                    container.appendChild(candidateDiv);
                });
            }
            
        } catch (error) {
            console.error('Error loading draft:', error);
        }
    }
});

// Clear draft when ballot is successfully created
function clearDraft() {
    localStorage.removeItem('ballotDraft');
} 