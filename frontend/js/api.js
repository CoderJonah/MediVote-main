/**
 * MediVote API Module
 * Centralized API interactions for the MediVote application
 */

// API Configuration
const API_CONFIG = {
    baseURL: 'http://localhost:8001',
    timeout: 30000,
    retryAttempts: 3,
    retryDelay: 1000
};

// API Endpoints
const API_ENDPOINTS = {
    // Authentication
    AUTH_REGISTER: '/api/auth/register',
    AUTH_LOGIN: '/api/auth/login',
    AUTH_LOGOUT: '/api/auth/logout',
    AUTH_REFRESH: '/api/auth/refresh',
    
    // Voting
    VOTING_BALLOTS: '/api/voting/ballots',
    VOTING_CAST: '/api/voting/cast-vote',
    VOTING_PREPARE: '/api/voting/prepare-ballot',
    VOTING_AUTHORIZE: '/api/voting/authorize-ballot',
    
    // Verification
    VERIFY_VOTE: '/api/verification/verify-vote',
    VERIFY_RECEIPT: '/api/verification/verify-receipt',
    VERIFY_PROOF: '/api/verification/verify-proof',
    
    // Admin
    ADMIN_RESULTS: '/api/admin/results',
    ADMIN_CREATE_BALLOT: '/api/admin/create-ballot',
    ADMIN_MANAGE_ELECTION: '/api/admin/manage-election',
    
    // System
    SYSTEM_STATUS: '/api/status',
    SYSTEM_HEALTH: '/health',
    SYSTEM_INFO: '/'
};

// API Client Class
class MediVoteAPIClient {
    constructor(config = API_CONFIG) {
        this.baseURL = config.baseURL;
        this.timeout = config.timeout;
        this.retryAttempts = config.retryAttempts;
        this.retryDelay = config.retryDelay;
        this.authToken = null;
    }

    /**
     * Set authentication token
     */
    setAuthToken(token) {
        this.authToken = token;
    }

    /**
     * Get authentication headers
     */
    getAuthHeaders() {
        const headers = {
            'Content-Type': 'application/json'
        };
        
        if (this.authToken) {
            headers['Authorization'] = `Bearer ${this.authToken}`;
        }
        
        return headers;
    }

    /**
     * Make HTTP request with retry logic
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            method: 'GET',
            headers: this.getAuthHeaders(),
            timeout: this.timeout,
            ...options
        };

        let lastError;
        
        for (let attempt = 0; attempt < this.retryAttempts; attempt++) {
            try {
                const response = await fetch(url, config);
                
                // Handle different response types
                let data;
                const contentType = response.headers.get('content-type');
                
                if (contentType && contentType.includes('application/json')) {
                    data = await response.json();
                } else {
                    data = await response.text();
                }
                
                if (!response.ok) {
                    throw new APIError(
                        data.detail || data.message || `HTTP ${response.status}`,
                        response.status,
                        data
                    );
                }
                
                return {
                    data,
                    status: response.status,
                    headers: response.headers
                };
                
            } catch (error) {
                lastError = error;
                
                // Don't retry on authentication errors
                if (error.status === 401 || error.status === 403) {
                    throw error;
                }
                
                // Wait before retrying
                if (attempt < this.retryAttempts - 1) {
                    await new Promise(resolve => setTimeout(resolve, this.retryDelay));
                }
            }
        }
        
        throw lastError;
    }

    /**
     * GET request
     */
    async get(endpoint, params = {}) {
        const queryString = new URLSearchParams(params).toString();
        const url = queryString ? `${endpoint}?${queryString}` : endpoint;
        
        return this.request(url, { method: 'GET' });
    }

    /**
     * POST request
     */
    async post(endpoint, data = {}) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    /**
     * PUT request
     */
    async put(endpoint, data = {}) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    /**
     * DELETE request
     */
    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }

    // Authentication Methods
    async register(userData) {
        return this.post(API_ENDPOINTS.AUTH_REGISTER, userData);
    }

    async login(credentials) {
        const response = await this.post(API_ENDPOINTS.AUTH_LOGIN, credentials);
        if (response.data.token) {
            this.setAuthToken(response.data.token);
        }
        return response;
    }

    async logout() {
        const response = await this.post(API_ENDPOINTS.AUTH_LOGOUT);
        this.authToken = null;
        return response;
    }

    // Voting Methods
    async getBallots() {
        return this.get(API_ENDPOINTS.VOTING_BALLOTS);
    }

    async castVote(voteData) {
        return this.post(API_ENDPOINTS.VOTING_CAST, voteData);
    }

    async prepareBallot(ballotData) {
        return this.post(API_ENDPOINTS.VOTING_PREPARE, ballotData);
    }

    async authorizeBallot(authData) {
        return this.post(API_ENDPOINTS.VOTING_AUTHORIZE, authData);
    }

    // Verification Methods
    async verifyVote(receiptId, verificationCode) {
        return this.get(API_ENDPOINTS.VERIFY_VOTE, { receipt_id: receiptId, verification_code: verificationCode });
    }

    async verifyReceipt(receiptData) {
        return this.post(API_ENDPOINTS.VERIFY_RECEIPT, receiptData);
    }

    async verifyProof(proofData) {
        return this.post(API_ENDPOINTS.VERIFY_PROOF, proofData);
    }

    // Admin Methods
    async getResults(ballotId) {
        return this.get(API_ENDPOINTS.ADMIN_RESULTS, { ballot_id: ballotId });
    }

    async createBallot(ballotData) {
        return this.post(API_ENDPOINTS.ADMIN_CREATE_BALLOT, ballotData);
    }

    async manageElection(electionData) {
        return this.post(API_ENDPOINTS.ADMIN_MANAGE_ELECTION, electionData);
    }

    // System Methods
    async getSystemStatus() {
        return this.get(API_ENDPOINTS.SYSTEM_STATUS);
    }

    async getSystemHealth() {
        return this.get(API_ENDPOINTS.SYSTEM_HEALTH);
    }

    async getSystemInfo() {
        return this.get(API_ENDPOINTS.SYSTEM_INFO);
    }
}

// Custom Error Class
class APIError extends Error {
    constructor(message, status, data) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.data = data;
    }
}

// API Response Handler
class APIResponseHandler {
    static handleSuccess(response, successMessage) {
        if (typeof window !== 'undefined' && window.AlertSystem) {
            window.AlertSystem.show(successMessage, 'success');
        }
        return response;
    }

    static handleError(error, context = 'API Request') {
        console.error(`${context} Error:`, error);
        
        let errorMessage = 'An unexpected error occurred';
        
        if (error instanceof APIError) {
            errorMessage = error.message;
        } else if (error.message) {
            errorMessage = error.message;
        }
        
        if (typeof window !== 'undefined' && window.AlertSystem) {
            window.AlertSystem.show(errorMessage, 'error');
        }
        
        throw error;
    }
}

// Request Interceptor
class RequestInterceptor {
    static addRequestInterceptor(apiClient, interceptor) {
        const originalRequest = apiClient.request.bind(apiClient);
        
        apiClient.request = async function(endpoint, options) {
            const modifiedOptions = await interceptor(endpoint, options);
            return originalRequest(endpoint, modifiedOptions);
        };
    }

    static addResponseInterceptor(apiClient, interceptor) {
        const originalRequest = apiClient.request.bind(apiClient);
        
        apiClient.request = async function(endpoint, options) {
            const response = await originalRequest(endpoint, options);
            return interceptor(response);
        };
    }
}

// Global API Instance
const apiClient = new MediVoteAPIClient();

// Export for use in other modules
if (typeof window !== 'undefined') {
    window.MediVoteAPI = apiClient;
    window.APIError = APIError;
    window.APIResponseHandler = APIResponseHandler;
    window.RequestInterceptor = RequestInterceptor;
    window.API_ENDPOINTS = API_ENDPOINTS;
}

// Export for Node.js environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        MediVoteAPIClient,
        APIError,
        APIResponseHandler,
        RequestInterceptor,
        API_ENDPOINTS,
        apiClient
    };
} 