// Voter Registration JavaScript
// Handles voter registration form and SSI integration

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('registrationForm');
    const submitBtn = document.getElementById('submitBtn');
    
    // Form validation
    form.addEventListener('input', validateForm);
    form.addEventListener('submit', handleSubmit);
    
    // Set minimum date for date of birth (18 years ago)
    const dobInput = document.getElementById('dateOfBirth');
    const eighteenYearsAgo = new Date();
    eighteenYearsAgo.setFullYear(eighteenYearsAgo.getFullYear() - 18);
    dobInput.max = eighteenYearsAgo.toISOString().split('T')[0];
});

function validateForm() {
    const formData = getFormData();
    const errors = [];
    
    // Validate required fields
    if (!FormValidator.validateRequired(formData.fullName)) {
        errors.push('Full name is required');
    }
    
    if (!FormValidator.validateEmail(formData.email)) {
        errors.push('Valid email address is required');
    }
    
    if (!FormValidator.validatePassword(formData.password)) {
        errors.push('Password must be at least 8 characters long');
    }
    
    if (formData.password !== formData.confirmPassword) {
        errors.push('Passwords do not match');
    }
    
    if (!FormValidator.validatePhone(formData.phone)) {
        errors.push('Valid phone number is required');
    }
    
    if (!FormValidator.validateRequired(formData.address)) {
        errors.push('Address is required');
    }
    
    if (!FormValidator.validateDate(formData.dateOfBirth)) {
        errors.push('Valid date of birth is required');
    }
    
    if (!FormValidator.validateRequired(formData.identityDocument)) {
        errors.push('Identity document number is required');
    }
    
    if (!formData.terms) {
        errors.push('You must agree to the terms of service');
    }
    
    if (!formData.eligibility) {
        errors.push('You must confirm your eligibility to vote');
    }
    
    // Update form validation state
    updateFormValidation(errors);
    
    return errors.length === 0;
}

function getFormData() {
    return {
        fullName: document.getElementById('fullName').value,
        email: document.getElementById('email').value,
        password: document.getElementById('password').value,
        confirmPassword: document.getElementById('confirmPassword').value,
        phone: document.getElementById('phone').value,
        address: document.getElementById('address').value,
        dateOfBirth: document.getElementById('dateOfBirth').value,
        identityDocument: document.getElementById('identityDocument').value,
        terms: document.getElementById('terms').checked,
        eligibility: document.getElementById('eligibility').checked
    };
}

function updateFormValidation(errors) {
    const submitBtn = document.getElementById('submitBtn');
    
    if (errors.length === 0) {
        submitBtn.disabled = false;
        submitBtn.classList.remove('btn-disabled');
    } else {
        submitBtn.disabled = true;
        submitBtn.classList.add('btn-disabled');
    }
}

async function handleSubmit(event) {
    event.preventDefault();
    
    if (!validateForm()) {
        AlertSystem.show('Please fix the form errors before submitting', 'error');
        return;
    }
    
    const formData = getFormData();
    const submitBtn = document.getElementById('submitBtn');
    
    // Show loading state
    const originalContent = submitBtn.innerHTML;
    submitBtn.innerHTML = '<div class="loading"></div> Registering...';
    submitBtn.disabled = true;
    
    try {
        // Prepare registration data
        const registrationData = {
            full_name: formData.fullName,
            email: formData.email,
            password: formData.password,
            phone: formData.phone,
            address: formData.address,
            date_of_birth: formData.dateOfBirth,
            identity_document: formData.identityDocument
        };
        
        // Submit registration
        const response = await MediVoteAPI.post('/api/auth/register', registrationData);
        
        // Show success message
        AlertSystem.clear();
        AlertSystem.show(
            'Registration successful! Your Self-Sovereign Identity has been created and verified.',
            'success'
        );
        
        // Display registration details
        displayRegistrationSuccess(response);
        
        // Clear form
        document.getElementById('registrationForm').reset();
        
    } catch (error) {
        console.error('Registration error:', error);
        AlertSystem.show(
            `Registration failed: ${error.message}`,
            'error'
        );
    } finally {
        // Reset button state
        submitBtn.innerHTML = originalContent;
        submitBtn.disabled = false;
    }
}

function displayRegistrationSuccess(response) {
    const successHtml = `
        <div class="registration-success">
            <div class="success-header">
                <h2>
                    <i class="fas fa-check-circle text-success"></i>
                    Registration Successful
                </h2>
            </div>
            
            <div class="success-details">
                <h3>Your Voter Credentials</h3>
                <div class="credential-item">
                    <strong>Voter DID:</strong>
                    <span id="voterDID">${response.voter_did}</span>
                    <button class="btn btn-outline btn-sm" onclick="copyToClipboard('voterDID')">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
                
                <div class="credential-item">
                    <strong>Identity Hash:</strong>
                    <span id="identityHash">${response.identity_hash}</span>
                    <button class="btn btn-outline btn-sm" onclick="copyToClipboard('identityHash')">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
                
                <div class="credential-item">
                    <strong>Registration Status:</strong>
                    <span>${response.status}</span>
                </div>
                
                <div class="credential-item">
                    <strong>Registration Date:</strong>
                    <span>${new Date().toLocaleString()}</span>
                </div>
            </div>
            
            <div class="ssi-features">
                <h3>Security Features Enabled</h3>
                <ul>
                    ${response.features_enabled.map(feature => `<li>${feature}</li>`).join('')}
                </ul>
            </div>
            
            <div class="success-actions">
                <button class="btn btn-outline" onclick="printCredentials()">
                    <i class="fas fa-print"></i>
                    Print Credentials
                </button>
                <button class="btn btn-primary" onclick="downloadCredentials()">
                    <i class="fas fa-download"></i>
                    Download Credentials
                </button>
                <a href="vote.html" class="btn btn-success">
                    <i class="fas fa-vote-yea"></i>
                    Start Voting
                </a>
            </div>
        </div>
    `;
    
    const container = document.createElement('div');
    container.innerHTML = successHtml;
    document.querySelector('.form-container').appendChild(container);
}

function printCredentials() {
    const credentialsContent = document.querySelector('.registration-success').innerHTML;
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Voter Registration Credentials</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .success-actions { display: none; }
                .btn { display: none; }
                .credential-item { 
                    display: flex; 
                    justify-content: space-between; 
                    margin: 10px 0; 
                    padding: 10px;
                    border: 1px solid #ccc;
                }
                .credential-item span {
                    font-family: monospace;
                    word-break: break-all;
                }
            </style>
        </head>
        <body>
            <h1>MediVote - Voter Registration Credentials</h1>
            ${credentialsContent}
        </body>
        </html>
    `);
    printWindow.document.close();
    printWindow.print();
}

function downloadCredentials() {
    const credentialsData = {
        voterDID: document.getElementById('voterDID').textContent,
        identityHash: document.getElementById('identityHash').textContent,
        timestamp: new Date().toISOString()
    };
    
    const dataStr = JSON.stringify(credentialsData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `voter_credentials_${credentialsData.voterDID.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
    link.click();
    
    URL.revokeObjectURL(url);
}

function clearForm() {
    document.getElementById('registrationForm').reset();
    AlertSystem.clear();
    
    // Remove any success displays
    const successElement = document.querySelector('.registration-success');
    if (successElement) {
        successElement.remove();
    }
}

// Phone number formatting
document.getElementById('phone').addEventListener('input', function(e) {
    let value = e.target.value.replace(/\D/g, '');
    if (value.length >= 6) {
        value = value.replace(/(\d{3})(\d{3})(\d{4})/, '($1) $2-$3');
    } else if (value.length >= 3) {
        value = value.replace(/(\d{3})(\d{3})/, '($1) $2');
    }
    e.target.value = value;
});

// Password strength indicator
document.getElementById('password').addEventListener('input', function(e) {
    const password = e.target.value;
    const strength = calculatePasswordStrength(password);
    updatePasswordStrength(strength);
});

function calculatePasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (password.match(/[a-z]/)) strength++;
    if (password.match(/[A-Z]/)) strength++;
    if (password.match(/[0-9]/)) strength++;
    if (password.match(/[^a-zA-Z0-9]/)) strength++;
    
    return strength;
}

function updatePasswordStrength(strength) {
    const strengthMeter = document.getElementById('passwordStrength');
    if (!strengthMeter) return;
    
    const levels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    const colors = ['#ef4444', '#f59e0b', '#eab308', '#22c55e', '#10b981'];
    
    strengthMeter.textContent = levels[strength - 1] || 'Very Weak';
    strengthMeter.style.color = colors[strength - 1] || colors[0];
}

// Add password strength meter to DOM
document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('password');
    const strengthMeter = document.createElement('div');
    strengthMeter.id = 'passwordStrength';
    strengthMeter.className = 'password-strength';
    strengthMeter.style.cssText = 'font-size: 0.875rem; margin-top: 0.25rem;';
    passwordInput.parentElement.appendChild(strengthMeter);
}); 