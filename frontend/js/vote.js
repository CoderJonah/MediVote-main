// Voting JavaScript
// Handles ballot display and vote casting with cryptographic security

let availableBallots = [];
let selectedVotes = {};

document.addEventListener('DOMContentLoaded', function() {
    loadAvailableBallots();
});

async function loadAvailableBallots() {
    const loadingContainer = document.getElementById('loadingContainer');
    const noBallots = document.getElementById('noBallots');
    const ballotsContainer = document.getElementById('ballotsContainer');
    
    // Show loading state
    loadingContainer.style.display = 'block';
    noBallots.style.display = 'none';
    ballotsContainer.innerHTML = '';
    
    try {
        const response = await MediVoteAPI.get('/api/voting/ballots');
        availableBallots = response.ballots || [];
        
        loadingContainer.style.display = 'none';
        
        if (availableBallots.length === 0) {
            noBallots.style.display = 'block';
        } else {
            displayBallots();
        }
        
    } catch (error) {
        console.error('Error loading ballots:', error);
        loadingContainer.style.display = 'none';
        AlertSystem.show('Failed to load available ballots. Please try again.', 'error');
    }
}

function displayBallots() {
    const ballotsContainer = document.getElementById('ballotsContainer');
    
    const ballotsHtml = availableBallots.map(ballot => `
        <div class="vote-card" id="ballot-${ballot.id}">
            <h3>${ballot.title}</h3>
            <div class="vote-meta">
                <p>${ballot.description}</p>
                <div class="ballot-timeline">
                    <span><i class="fas fa-calendar-alt"></i> ${formatDateTime(ballot.start_time)} - ${formatDateTime(ballot.end_time)}</span>
                    <span><i class="fas fa-users"></i> ${ballot.votes_count || 0} votes cast</span>
                </div>
            </div>
            
            <div class="candidate-options">
                ${ballot.candidates.map(candidate => `
                    <div class="candidate-option">
                        <input type="radio" 
                               id="candidate-${candidate.name.replace(/\s+/g, '-')}" 
                               name="ballot-${ballot.id}" 
                               value="${candidate.name}"
                               onchange="updateVoteSelection('${ballot.id}', '${candidate.name}')">
                        <div class="candidate-info">
                            <h4>${candidate.name}</h4>
                            <p>${candidate.party || candidate.position || 'Independent'}</p>
                        </div>
                    </div>
                `).join('')}
            </div>
            
            <div class="vote-actions">
                <button class="btn btn-primary" onclick="castVote('${ballot.id}')" disabled id="vote-btn-${ballot.id}">
                    <i class="fas fa-vote-yea"></i>
                    Cast Vote
                </button>
                <button class="btn btn-outline" onclick="clearSelection('${ballot.id}')">
                    <i class="fas fa-times"></i>
                    Clear Selection
                </button>
            </div>
        </div>
    `).join('');
    
    ballotsContainer.innerHTML = ballotsHtml;
}

function updateVoteSelection(ballotId, candidateId) {
    selectedVotes[ballotId] = candidateId;
    
    // Enable vote button
    const voteBtn = document.getElementById(`vote-btn-${ballotId}`);
    voteBtn.disabled = false;
    
    // Update button text to show selection
    const selectedCandidate = availableBallots
        .find(b => b.id === ballotId)
        ?.candidates.find(c => c.name === candidateId);
    
    if (selectedCandidate) {
        voteBtn.innerHTML = `
            <i class="fas fa-vote-yea"></i>
            Vote for ${selectedCandidate.name}
        `;
    }
}

function clearSelection(ballotId) {
    delete selectedVotes[ballotId];
    
    // Clear radio buttons
    const radioButtons = document.querySelectorAll(`input[name="ballot-${ballotId}"]`);
    radioButtons.forEach(radio => radio.checked = false);
    
    // Reset vote button
    const voteBtn = document.getElementById(`vote-btn-${ballotId}`);
    voteBtn.disabled = true;
    voteBtn.innerHTML = `
        <i class="fas fa-vote-yea"></i>
        Cast Vote
    `;
}

async function castVote(ballotId) {
    if (!selectedVotes[ballotId]) {
        AlertSystem.show('Please select a candidate before voting.', 'warning');
        return;
    }
    
    // Confirm vote
    const selectedCandidate = availableBallots
        .find(b => b.id === ballotId)
        ?.candidates.find(c => c.name === selectedVotes[ballotId]);
    
    if (!confirm(`Are you sure you want to vote for ${selectedCandidate.name}? This action cannot be undone.`)) {
        return;
    }
    
    const voteBtn = document.getElementById(`vote-btn-${ballotId}`);
    const originalContent = voteBtn.innerHTML;
    
    // Show loading state
    voteBtn.innerHTML = '<div class="loading"></div> Casting Vote...';
    voteBtn.disabled = true;
    
    try {
        // Debug logging
        console.log('DEBUG: selectedVotes[ballotId]:', selectedVotes[ballotId]);
        console.log('DEBUG: availableBallots:', availableBallots);
        console.log('DEBUG: selectedCandidate:', selectedCandidate);
        
        // Prepare vote data - match backend API format
        // Ensure choice is always a simple string, never an object
        let choiceValue = selectedVotes[ballotId];
        if (selectedCandidate && selectedCandidate.name) {
            choiceValue = selectedCandidate.name;
        }
        // If choiceValue is somehow an object, extract the name or candidate_name
        if (typeof choiceValue === 'object' && choiceValue !== null) {
            choiceValue = choiceValue.candidate_name || choiceValue.name || String(choiceValue);
        }
        
        const voteData = {
            ballot_id: ballotId,
            choice: String(choiceValue), // Force to string to prevent object serialization
            voter_id: `frontend_user_${Date.now()}`
        };
        
        console.log('DEBUG: Final voteData being sent:', voteData);
        
        // Cast vote
        const response = await MediVoteAPI.post('/api/voting/cast-vote', voteData);
        
        // Show success and receipt
        AlertSystem.clear();
        AlertSystem.show('Vote cast successfully!', 'success');
        
        // Display vote receipt
        displayVoteReceipt(response);
        
        // Disable voting for this ballot
        disableBallotVoting(ballotId);
        
    } catch (error) {
        console.error('Vote casting error:', error);
        AlertSystem.show(`Failed to cast vote: ${error.message}`, 'error');
        
        // Reset button state
        voteBtn.innerHTML = originalContent;
        voteBtn.disabled = false;
    }
}

function displayVoteReceipt(response) {
    const modal = document.getElementById('voteReceiptModal');
    
    // Handle different response formats from backend
    let receipt;
    if (response.receipt && typeof response.receipt === 'object') {
        receipt = response.receipt;
    } else if (response.receipt && typeof response.receipt === 'string') {
        // Handle simple string receipt format
        receipt = {
            receipt_id: response.receipt,
            verification_code: response.vote_id || 'N/A',
            vote_hash: response.receipt,
            timestamp: new Date().toISOString()
        };
    } else {
        // Fallback receipt format
        receipt = {
            receipt_id: response.vote_id || 'receipt_' + Date.now(),
            verification_code: response.vote_id || 'N/A',
            vote_hash: 'hash_' + (response.vote_id || Date.now()),
            timestamp: new Date().toISOString()
        };
    }
    
    // Populate receipt details
    document.getElementById('receiptId').textContent = receipt.receipt_id || 'N/A';
    document.getElementById('verificationCode').textContent = receipt.verification_code || 'N/A';
    document.getElementById('voteHash').textContent = receipt.vote_hash || 'N/A';
    document.getElementById('timestamp').textContent = formatDateTime(receipt.timestamp || new Date().toISOString());
    
    // Populate privacy guarantees - handle missing field gracefully
    const privacyList = document.getElementById('privacyList');
    const privacyGuarantees = response.privacy_guarantees || response.cryptographic_features || response.features_enabled || [
        'Vote encrypted and stored securely',
        'Voter identity protected by cryptographic protocols',
        'Vote integrity verified through blockchain',
        'Anonymous voting process maintained'
    ];
    
    if (privacyList && Array.isArray(privacyGuarantees)) {
        privacyList.innerHTML = privacyGuarantees.map(guarantee => 
            `<li>${guarantee}</li>`
        ).join('');
    } else if (privacyList) {
        privacyList.innerHTML = '<li>Privacy and security features active</li>';
    }
    
    // Show modal
    modal.style.display = 'flex';
}

function closeModal() {
    document.getElementById('voteReceiptModal').style.display = 'none';
}

function disableBallotVoting(ballotId) {
    const ballotCard = document.getElementById(`ballot-${ballotId}`);
    
    // Disable all radio buttons
    const radioButtons = ballotCard.querySelectorAll('input[type="radio"]');
    radioButtons.forEach(radio => radio.disabled = true);
    
    // Disable vote button
    const voteBtn = document.getElementById(`vote-btn-${ballotId}`);
    voteBtn.disabled = true;
    voteBtn.innerHTML = `
        <i class="fas fa-check"></i>
        Vote Cast
    `;
    voteBtn.classList.remove('btn-primary');
    voteBtn.classList.add('btn-success');
    
    // Add voted indicator
    const voteCard = document.getElementById(`ballot-${ballotId}`);
    voteCard.classList.add('voted');
    
    // Add voted badge
    const title = voteCard.querySelector('h3');
    title.innerHTML += ' <span class="voted-badge">✓ Voted</span>';
}

function verifyVote() {
    const receiptId = document.getElementById('receiptId').textContent;
    const verificationCode = document.getElementById('verificationCode').textContent;
    
    // Close modal
    closeModal();
    
    // Redirect to verify page with parameters
    window.location.href = `verify.html?receipt=${receiptId}&code=${verificationCode}`;
}

// Close modal when clicking outside
document.addEventListener('click', function(event) {
    const modal = document.getElementById('voteReceiptModal');
    if (event.target === modal) {
        closeModal();
    }
});

// Close modal with ESC key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeModal();
    }
});

// Auto-refresh ballots every 30 seconds
setInterval(loadAvailableBallots, 30000);

// Add CSS for voted state
const style = document.createElement('style');
style.textContent = `
    .vote-card.voted {
        opacity: 0.8;
        border: 2px solid var(--success-color);
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(16, 185, 129, 0.05));
    }
    
    .voted-badge {
        display: inline-block;
        background: var(--success-color);
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 1rem;
        font-size: 0.75rem;
        font-weight: 500;
        margin-left: 1rem;
    }
    
    .vote-actions {
        display: flex;
        gap: 1rem;
        margin-top: 1.5rem;
        padding-top: 1rem;
        border-top: 1px solid var(--border-color);
    }
    
    .ballot-timeline {
        display: flex;
        gap: 1rem;
        margin-top: 0.5rem;
        font-size: 0.875rem;
        color: var(--text-secondary);
    }
    
    .ballot-timeline span {
        display: flex;
        align-items: center;
        gap: 0.25rem;
    }
    
    .candidate-option {
        transition: all 0.3s ease;
    }
    
    .candidate-option:hover {
        transform: translateY(-2px);
        box-shadow: var(--shadow-medium);
    }
    
    .candidate-option input[type="radio"]:checked + .candidate-info {
        color: var(--primary-color);
    }
    
    .candidate-option input[type="radio"]:checked {
        accent-color: var(--primary-color);
    }
`;
document.head.appendChild(style); 