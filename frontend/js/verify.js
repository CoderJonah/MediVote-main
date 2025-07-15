// Vote Verification JavaScript
// Handles vote verification using receipt ID and verification code

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('verificationForm');
    form.addEventListener('submit', handleVerification);
    
    // Check for URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const receiptId = urlParams.get('receipt');
    const verificationCode = urlParams.get('code');
    
    if (receiptId && verificationCode) {
        document.getElementById('receiptId').value = receiptId;
        document.getElementById('verificationCode').value = verificationCode;
        
        // Auto-verify if parameters are present
        setTimeout(() => {
            handleVerification({ preventDefault: () => {} });
        }, 500);
    }
});

async function handleVerification(event) {
    event.preventDefault();
    
    const receiptId = document.getElementById('receiptId').value.trim();
    const verificationCode = document.getElementById('verificationCode').value.trim();
    
    if (!receiptId || !verificationCode) {
        AlertSystem.show('Please enter both receipt ID and verification code.', 'warning');
        return;
    }
    
    const submitBtn = document.querySelector('button[type="submit"]');
    const originalContent = submitBtn.innerHTML;
    
    // Show loading state
    submitBtn.innerHTML = '<div class="loading"></div> Verifying...';
    submitBtn.disabled = true;
    
    try {
        // Verify vote
        const response = await MediVoteAPI.get(
            `/api/verification/verify-vote?receipt_id=${receiptId}&verification_code=${verificationCode}`
        );
        
        // Display verification result
        displayVerificationResult(response);
        
        // Show success message
        AlertSystem.clear();
        AlertSystem.show('Vote verification successful!', 'success');
        
    } catch (error) {
        console.error('Verification error:', error);
        AlertSystem.show(`Vote verification failed: ${error.message}`, 'error');
        
        // Hide result if there was an error
        document.getElementById('verificationResult').style.display = 'none';
        
    } finally {
        // Reset button state
        submitBtn.innerHTML = originalContent;
        submitBtn.disabled = false;
    }
}

function displayVerificationResult(response) {
    const resultContainer = document.getElementById('verificationResult');
    
    // Populate vote information
    document.getElementById('resultReceiptId').textContent = response.receipt_id;
    document.getElementById('resultVoteHash').textContent = response.vote_hash;
    document.getElementById('resultTimestamp').textContent = formatDateTime(response.timestamp);
    document.getElementById('resultBallotId').textContent = response.ballot_id;
    
    // Populate cryptographic proofs
    const proofs = response.cryptographic_proof;
    document.getElementById('zkProof').textContent = proofs.zk_proof;
    document.getElementById('blindSignature').textContent = proofs.blind_signature;
    document.getElementById('homomorphicTag').textContent = proofs.homomorphic_tag;
    
    // Show result
    resultContainer.style.display = 'block';
    
    // Scroll to result
    resultContainer.scrollIntoView({ behavior: 'smooth' });
}

function clearForm() {
    document.getElementById('verificationForm').reset();
    document.getElementById('verificationResult').style.display = 'none';
    AlertSystem.clear();
}

function downloadProof() {
    const verificationData = {
        receiptId: document.getElementById('resultReceiptId').textContent,
        voteHash: document.getElementById('resultVoteHash').textContent,
        timestamp: document.getElementById('resultTimestamp').textContent,
        ballotId: document.getElementById('resultBallotId').textContent,
        cryptographicProof: {
            zkProof: document.getElementById('zkProof').textContent,
            blindSignature: document.getElementById('blindSignature').textContent,
            homomorphicTag: document.getElementById('homomorphicTag').textContent
        },
        verificationTimestamp: new Date().toISOString()
    };
    
    const dataStr = JSON.stringify(verificationData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `vote_verification_${verificationData.receiptId}.json`;
    link.click();
    
    URL.revokeObjectURL(url);
}

function printVerification() {
    const verificationContent = document.getElementById('verificationResult').innerHTML;
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vote Verification Report</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 20px; 
                    line-height: 1.6;
                }
                .verification-actions { display: none; }
                .btn { display: none; }
                .result-header {
                    text-align: center;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 2px solid #2563eb;
                }
                .detail-section {
                    margin-bottom: 30px;
                }
                .detail-section h3 {
                    color: #2563eb;
                    border-bottom: 1px solid #e2e8f0;
                    padding-bottom: 10px;
                }
                .detail-item {
                    margin: 10px 0;
                    padding: 10px;
                    background: #f8fafc;
                    border-radius: 5px;
                }
                .detail-item strong {
                    color: #1e293b;
                }
                .detail-item span {
                    font-family: monospace;
                    word-break: break-all;
                    color: #64748b;
                }
                .proof-item {
                    margin: 15px 0;
                    padding: 15px;
                    background: #f0f9ff;
                    border-left: 4px solid #10b981;
                    border-radius: 5px;
                }
                .proof-item h4 {
                    color: #1e293b;
                    margin-bottom: 10px;
                }
                .proof-item code {
                    background: #e2e8f0;
                    padding: 5px;
                    border-radius: 3px;
                    font-size: 12px;
                    word-break: break-all;
                    display: block;
                    margin-top: 5px;
                }
                .status-check {
                    display: flex;
                    align-items: center;
                    margin: 8px 0;
                    padding: 8px;
                    background: #f0fdf4;
                    border-radius: 5px;
                }
                .status-check i {
                    color: #10b981;
                    margin-right: 10px;
                }
                @media print {
                    body { margin: 0; }
                    .verification-actions { display: none !important; }
                }
            </style>
        </head>
        <body>
            <div style="text-align: center; margin-bottom: 30px;">
                <h1>MediVote - Vote Verification Report</h1>
                <p>Generated on: ${new Date().toLocaleString()}</p>
            </div>
            ${verificationContent}
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ccc; text-align: center; color: #666;">
                <p>This verification report confirms that your vote was properly recorded and secured using advanced cryptographic protocols.</p>
            </div>
        </body>
        </html>
    `);
    printWindow.document.close();
    printWindow.print();
}

// Input validation and formatting
document.getElementById('receiptId').addEventListener('input', function(e) {
    // Remove any non-alphanumeric characters except underscores
    e.target.value = e.target.value.replace(/[^a-zA-Z0-9_]/g, '');
});

document.getElementById('verificationCode').addEventListener('input', function(e) {
    // Convert to uppercase and remove invalid characters
    e.target.value = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
});

// Add helpful tooltips
const tooltips = {
    receiptId: 'This is the unique receipt ID you received after voting (e.g., receipt_abc123...)',
    verificationCode: 'This is the verification code shown on your vote receipt (e.g., A1B2C3D4)'
};

Object.entries(tooltips).forEach(([id, tooltip]) => {
    const element = document.getElementById(id);
    if (element) {
        element.setAttribute('title', tooltip);
        element.addEventListener('focus', function() {
            showTooltip(this, tooltip);
        });
        element.addEventListener('blur', hideTooltip);
    }
});

function showTooltip(element, text) {
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    tooltip.textContent = text;
    tooltip.style.cssText = `
        position: absolute;
        background: #1f2937;
        color: white;
        padding: 8px 12px;
        border-radius: 4px;
        font-size: 0.875rem;
        z-index: 1000;
        white-space: nowrap;
        max-width: 300px;
        white-space: normal;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    `;
    
    document.body.appendChild(tooltip);
    
    const rect = element.getBoundingClientRect();
    tooltip.style.left = rect.left + 'px';
    tooltip.style.top = (rect.bottom + 8) + 'px';
    
    element._tooltip = tooltip;
}

function hideTooltip(e) {
    if (e.target._tooltip) {
        e.target._tooltip.remove();
        delete e.target._tooltip;
    }
}

// Add example values for demonstration
function showExample() {
    document.getElementById('receiptId').value = 'receipt_abc123def456';
    document.getElementById('verificationCode').value = 'A1B2C3D4';
    
    AlertSystem.show('Example values filled in. Click "Verify Vote" to test.', 'info');
}

// Add example button
document.addEventListener('DOMContentLoaded', function() {
    const exampleBtn = document.createElement('button');
    exampleBtn.type = 'button';
    exampleBtn.className = 'btn btn-outline btn-sm';
    exampleBtn.innerHTML = '<i class="fas fa-lightbulb"></i> Fill Example';
    exampleBtn.onclick = showExample;
    exampleBtn.style.marginTop = '1rem';
    
    document.querySelector('.form-container').appendChild(exampleBtn);
}); 