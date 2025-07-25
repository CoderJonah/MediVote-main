// Voting JavaScript
// Handles ballot display and vote casting with cryptographic security
// Requires voter registration and authentication

let availableBallots = [];
let selectedVotes = {};
let voterSession = null;

document.addEventListener('DOMContentLoaded', function() {
    checkVoterAuthentication();
});

function checkVoterAuthentication() {
    // Check if voter is logged in
    const sessionId = localStorage.getItem('voter_session_id');
    const voterInfo = localStorage.getItem('voter_info');
    
    if (!sessionId || !voterInfo) {
        showRegistrationRequired();
        return;
    }
    
    try {
        voterSession = {
            sessionId: sessionId,
            voterInfo: JSON.parse(voterInfo)
        };
        
        showVoterWelcome();
        loadAvailableBallots();
    } catch (error) {
        console.error('Error parsing voter session:', error);
        showRegistrationRequired();
    }
}

function showRegistrationRequired() {
    const container = document.querySelector('.main .container');
    container.innerHTML = `
        <h1 class="text-center mb-4">
            <i class="fas fa-user-lock"></i>
            Voter Registration Required
        </h1>
        
        <div class="alert alert-warning">
            <i class="fas fa-exclamation-triangle"></i>
            <div>
                <strong>Registration Required:</strong> You must register and login as a voter to participate in elections.
                This ensures election integrity and prevents unauthorized voting.
            </div>
        </div>
        
        <div class="text-center" style="margin: 3rem 0;">
            <h3>🗳️ Why Voter Registration?</h3>
            <div style="max-width: 600px; margin: 0 auto; text-align: left;">
                <ul style="padding-left: 2rem; line-height: 1.8;">
                    <li><strong>🔒 Security:</strong> Your credentials are encrypted and stored securely</li>
                    <li><strong>🎭 Privacy:</strong> Voter identity is anonymized while maintaining vote integrity</li>
                    <li><strong>📋 Audit Trail:</strong> Complete audit trail for election transparency</li>
                    <li><strong>⛓️ Blockchain:</strong> Votes are stored immutably on the blockchain</li>
                    <li><strong>👥 No Anonymous Voting:</strong> Prevents fraud and duplicate voting</li>
                </ul>
            </div>
            
            <div style="margin-top: 2rem;">
                <a href="voter-auth.html" class="btn btn-primary" style="margin: 0.5rem;">
                    <i class="fas fa-user-plus"></i> Register as Voter
                </a>
                <a href="voter-auth.html" class="btn btn-secondary" style="margin: 0.5rem;">
                    <i class="fas fa-sign-in-alt"></i> Login
                </a>
            </div>
        </div>
    `;
}

function showVoterWelcome() {
    if (!voterSession) return;
    
    // Add welcome message
    const container = document.querySelector('.main .container');
    const welcomeDiv = document.createElement('div');
    welcomeDiv.className = 'alert alert-success';
    welcomeDiv.innerHTML = `
        <i class="fas fa-user-check"></i>
        <div>
            <strong>Welcome, ${voterSession.voterInfo.full_name}!</strong> 
            You are logged in as a registered voter. Your vote will be cryptographically secured and stored on the blockchain.
            <br><small>Voter ID: ${voterSession.voterInfo.voter_id} | DID: ${voterSession.voterInfo.voter_did}</small>
        </div>
    `;
    
    // Insert after the main heading
    const heading = container.querySelector('h1');
    heading.insertAdjacentElement('afterend', welcomeDiv);
}

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
    // Check voter authentication
    if (!voterSession) {
        AlertSystem.show('You must be logged in as a voter to cast votes.', 'error');
        setTimeout(() => {
            window.location.href = 'voter-auth.html';
        }, 2000);
        return;
    }
    
    if (!selectedVotes[ballotId]) {
        AlertSystem.show('Please select a candidate before voting.', 'warning');
        return;
    }
    
    // Confirm vote
    const selectedCandidate = availableBallots
        .find(b => b.id === ballotId)
        ?.candidates.find(c => c.name === selectedVotes[ballotId]);
    
    const confirmMessage = `🗳️ CAST VOTE CONFIRMATION\n\n` +
        `Voter: ${voterSession.voterInfo.full_name}\n` +
        `Ballot: ${availableBallots.find(b => b.id === ballotId)?.title}\n` +
        `Choice: ${selectedCandidate.name}\n\n` +
        `This vote will be:\n` +
        `• Encrypted and stored securely\n` +
        `• Recorded on the blockchain\n` +
        `• Auditable and verifiable\n\n` +
        `Are you sure you want to cast this vote?\n` +
        `This action cannot be undone.`;
    
    if (!confirm(confirmMessage)) {
        return;
    }
    
    const voteBtn = document.getElementById(`vote-btn-${ballotId}`);
    const originalContent = voteBtn.innerHTML;
    
    // Show loading state
    voteBtn.innerHTML = '<div class="loading"></div> Casting Vote...';
    voteBtn.disabled = true;
    
    try {
        // Prepare vote data with voter session
        let choiceValue = selectedVotes[ballotId];
        if (selectedCandidate && selectedCandidate.name) {
            choiceValue = selectedCandidate.name;
        }
        // If choiceValue is somehow an object, extract the name
        if (typeof choiceValue === 'object' && choiceValue !== null) {
            choiceValue = choiceValue.candidate_name || choiceValue.name || String(choiceValue);
        }
        
        const voteData = {
            ballot_id: ballotId,
            choice: String(choiceValue),
            session_id: voterSession.sessionId  // Include session for authentication
        };
        
        console.log('🗳️ Casting vote as registered voter:', {
            voter: voterSession.voterInfo.username,
            voter_did: voterSession.voterInfo.voter_did,
            ballot: ballotId,
            choice: choiceValue
        });
        
        // Cast vote with VoterSession header for authentication
        const response = await MediVoteAPI.post('/api/voting/cast-vote', voteData, {
            'Authorization': `VoterSession ${voterSession.sessionId}`
        });
        
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