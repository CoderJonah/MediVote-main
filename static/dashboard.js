
// Dashboard JavaScript
class MediVoteDashboard {
    constructor() {
        this.refreshInterval = 30000; // 30 seconds
        this.init();
    }
    
    init() {
        this.loadStats();
        this.loadNodes();
        this.loadElections();
        
        // Auto-refresh
        setInterval(() => {
            this.loadStats();
            this.loadNodes();
            this.loadElections();
        }, this.refreshInterval);
        
        // Manual refresh button
        document.getElementById('refresh-btn').addEventListener('click', () => {
            this.loadStats();
            this.loadNodes();
            this.loadElections();
        });
    }
    
    async loadStats() {
        try {
            const response = await fetch('/api/stats');
            const stats = await response.json();
            this.updateStats(stats);
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }
    
    async loadNodes() {
        try {
            const response = await fetch('/api/nodes');
            const nodes = await response.json();
            this.updateNodes(nodes);
        } catch (error) {
            console.error('Failed to load nodes:', error);
        }
    }
    
    async loadElections() {
        try {
            const response = await fetch('/api/elections');
            const elections = await response.json();
            this.updateElections(elections);
        } catch (error) {
            console.error('Failed to load elections:', error);
        }
    }
    
    updateStats(stats) {
        document.getElementById('total-nodes').textContent = stats.total_nodes;
        document.getElementById('active-nodes').textContent = stats.active_nodes;
        document.getElementById('total-votes').textContent = stats.total_votes;
        document.getElementById('total-elections').textContent = stats.total_elections;
        document.getElementById('network-uptime').textContent = stats.network_uptime;
        document.getElementById('last-updated').textContent = new Date(stats.last_updated).toLocaleString();
    }
    
    updateNodes(nodes) {
        const container = document.getElementById('nodes-container');
        container.innerHTML = '';
        
        nodes.forEach(node => {
            const nodeCard = document.createElement('div');
            nodeCard.className = `node-card ${node.is_active ? 'active' : 'inactive'}`;
            
            nodeCard.innerHTML = `
                <h4>${node.node_id}</h4>
                <span class="status ${node.is_active ? 'active' : 'inactive'}">
                    ${node.is_active ? 'Active' : 'Inactive'}
                </span>
                <div class="details">
                    <div>Address: ${node.address}:${node.port}</div>
                    <div>Type: ${node.node_type}</div>
                    <div>Votes: ${node.votes_processed}</div>
                    <div>Blocks: ${node.blocks_processed}</div>
                    <div>Last Seen: ${new Date(node.last_seen).toLocaleString()}</div>
                </div>
            `;
            
            container.appendChild(nodeCard);
        });
    }
    
    updateElections(elections) {
        const container = document.getElementById('elections-container');
        container.innerHTML = '';
        
        elections.forEach(election => {
            const electionCard = document.createElement('div');
            electionCard.className = 'node-card';
            
            electionCard.innerHTML = `
                <h4>${election.election_id}</h4>
                <div class="details">
                    <div>Status: ${election.status}</div>
                    <div>Total Votes: ${election.total_votes}</div>
                    <div>Start Date: ${new Date(election.start_date).toLocaleDateString()}</div>
                    <div>End Date: ${new Date(election.end_date).toLocaleDateString()}</div>
                </div>
            `;
            
            container.appendChild(electionCard);
        });
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    new MediVoteDashboard();
});
