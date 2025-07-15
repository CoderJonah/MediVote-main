// MediVote Main JavaScript
// Common functionality and API interactions

// Configuration
const API_BASE_URL = 'http://localhost:8000';

// Common utility functions
class MediVoteAPI {
    static async request(endpoint, options = {}) {
        const url = `${API_BASE_URL}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        try {
            const response = await fetch(url, config);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.detail || data.message || 'Request failed');
            }
            
            return data;
        } catch (error) {
            console.error('API Request Error:', error);
            throw error;
        }
    }

    static async get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    }

    static async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    static async put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    static async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }
}

// Alert system
class AlertSystem {
    static show(message, type = 'info', container = 'alertContainer') {
        const alertContainer = document.getElementById(container);
        if (!alertContainer) return;

        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        
        const icon = this.getIcon(type);
        alert.innerHTML = `
            <i class="fas ${icon}"></i>
            <div>${message}</div>
            <button class="alert-close" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;

        alertContainer.appendChild(alert);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alert.parentElement) {
                alert.remove();
            }
        }, 5000);
    }

    static getIcon(type) {
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        return icons[type] || icons.info;
    }

    static clear(container = 'alertContainer') {
        const alertContainer = document.getElementById(container);
        if (alertContainer) {
            alertContainer.innerHTML = '';
        }
    }
}

// Loading states
class LoadingManager {
    static show(element, message = 'Loading...') {
        if (typeof element === 'string') {
            element = document.getElementById(element);
        }
        if (!element) return;

        element.innerHTML = `
            <div class="loading-container text-center">
                <div class="loading"></div>
                <p>${message}</p>
            </div>
        `;
    }

    static hide(element) {
        if (typeof element === 'string') {
            element = document.getElementById(element);
        }
        if (!element) return;

        element.innerHTML = '';
    }
}

// System status checker
class SystemStatus {
    static async checkStatus() {
        try {
            const status = await MediVoteAPI.get('/api/status');
            this.updateStatusDisplay(status);
            return status;
        } catch (error) {
            console.error('Failed to check system status:', error);
            this.updateStatusDisplay(null);
            return null;
        }
    }

    static updateStatusDisplay(status) {
        const statusElements = {
            backendStatus: document.getElementById('backendStatus'),
            databaseStatus: document.getElementById('databaseStatus'),
            blockchainStatus: document.getElementById('blockchainStatus'),
            cacheStatus: document.getElementById('cacheStatus')
        };

        if (!status) {
            Object.values(statusElements).forEach(element => {
                if (element) {
                    element.textContent = 'Error';
                    element.className = 'status-badge error';
                }
            });
            return;
        }

        // Update backend status
        if (statusElements.backendStatus) {
            statusElements.backendStatus.textContent = status.status === 'operational' ? 'Operational' : 'Error';
            statusElements.backendStatus.className = `status-badge ${status.status === 'operational' ? 'healthy' : 'error'}`;
        }

        // Update database status (from infrastructure object)
        if (statusElements.databaseStatus) {
            const dbStatus = status.infrastructure?.database || 'Unknown';
            statusElements.databaseStatus.textContent = dbStatus;
            statusElements.databaseStatus.className = `status-badge ${dbStatus === 'connected' ? 'healthy' : 'error'}`;
        }

        // Update blockchain status (from infrastructure object)
        if (statusElements.blockchainStatus) {
            const blockchainStatus = status.infrastructure?.blockchain || 'Unknown';
            statusElements.blockchainStatus.textContent = blockchainStatus;
            statusElements.blockchainStatus.className = `status-badge ${blockchainStatus === 'synchronized' ? 'healthy' : 'error'}`;
        }

        // Update cache status (simulate cache status)
        if (statusElements.cacheStatus) {
            const cacheStatus = status.infrastructure?.api_endpoints === 'responsive' ? 'Active' : 'Unknown';
            statusElements.cacheStatus.textContent = cacheStatus;
            statusElements.cacheStatus.className = `status-badge ${cacheStatus === 'Active' ? 'healthy' : 'error'}`;
        }
    }
}

// Form validation utilities
class FormValidator {
    static validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    static validatePassword(password) {
        return password.length >= 8;
    }

    static validatePhone(phone) {
        const phoneRegex = /^\+?[\d\s\-\(\)]+$/;
        return phoneRegex.test(phone) && phone.replace(/\D/g, '').length >= 10;
    }

    static validateRequired(value) {
        return value && value.trim().length > 0;
    }

    static validateDate(date) {
        const dateObj = new Date(date);
        return !isNaN(dateObj.getTime()) && dateObj < new Date();
    }
}

// Clipboard utilities
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const text = element.textContent;
    navigator.clipboard.writeText(text).then(() => {
        AlertSystem.show('Copied to clipboard!', 'success');
    }).catch(() => {
        AlertSystem.show('Failed to copy to clipboard', 'error');
    });
}

// Print utilities
function printReceipt() {
    const printContent = document.getElementById('voteReceiptModal').innerHTML;
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vote Receipt</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .modal-content { box-shadow: none; }
                .modal-header, .modal-footer { display: none; }
                .btn { display: none; }
                .close-btn { display: none; }
            </style>
        </head>
        <body>
            <h1>MediVote - Vote Receipt</h1>
            ${printContent}
        </body>
        </html>
    `);
    printWindow.document.close();
    printWindow.print();
}

function printVerification() {
    const printContent = document.getElementById('verificationResult').innerHTML;
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vote Verification</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .verification-actions { display: none; }
                .btn { display: none; }
            </style>
        </head>
        <body>
            <h1>MediVote - Vote Verification</h1>
            ${printContent}
        </body>
        </html>
    `);
    printWindow.document.close();
    printWindow.print();
}

// Download utilities
function downloadProof() {
    const verificationData = {
        receiptId: document.getElementById('resultReceiptId').textContent,
        voteHash: document.getElementById('resultVoteHash').textContent,
        timestamp: document.getElementById('resultTimestamp').textContent,
        zkProof: document.getElementById('zkProof').textContent,
        blindSignature: document.getElementById('blindSignature').textContent,
        homomorphicTag: document.getElementById('homomorphicTag').textContent
    };

    const dataStr = JSON.stringify(verificationData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `vote_proof_${verificationData.receiptId}.json`;
    link.click();
    
    URL.revokeObjectURL(url);
}

// Date formatting utilities
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Initialize system status on page load
document.addEventListener('DOMContentLoaded', function() {
    // Check system status
    SystemStatus.checkStatus();
    
    // Refresh status every 30 seconds
    setInterval(() => {
        SystemStatus.checkStatus();
    }, 30000);
    
    // Set up navigation active states
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === currentPage) {
            link.classList.add('active');
        }
    });
});

// Error handling
window.addEventListener('error', function(event) {
    console.error('Global error:', event.error);
    AlertSystem.show('An unexpected error occurred. Please try again.', 'error');
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        MediVoteAPI,
        AlertSystem,
        LoadingManager,
        SystemStatus,
        FormValidator
    };
} 