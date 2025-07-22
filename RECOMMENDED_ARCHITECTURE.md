# MediVote Recommended Architecture

## For Development/Demo (Single PC)

Run **one instance** of each service:
- ✅ 1 Backend API Server (port 8001)
- ✅ 1 Blockchain Node (port 8546)
- ✅ 1 Frontend Server (port 8080)
- ✅ 1 Incentive System (port 8082)
- ✅ 1 Network Coordinator (port 8083)
- ✅ 1 Network Dashboard (port 8084)

## For Production (Distributed Network)

### Minimum Setup (3 Machines)
1. **Machine 1**: Backend API + Frontend
2. **Machine 2**: Blockchain Node 1
3. **Machine 3**: Blockchain Node 2

### Recommended Setup (5+ Machines)
1. **Load Balancer**: Nginx/HAProxy
2. **API Servers** (2+): Backend services
3. **Blockchain Nodes** (3+): Distributed consensus
4. **Database Server**: PostgreSQL cluster
5. **Monitoring**: Network dashboard + metrics

## Why Not Multiple Nodes on Same PC?

1. **No Real Decentralization**: All nodes fail if the PC fails
2. **Resource Waste**: Duplicate processing of same data
3. **Port Conflicts**: Services fighting for resources
4. **Unrealistic Testing**: Doesn't simulate real network conditions

## Quick Fix for Current Setup

Update the service manager to only show one blockchain node:

```python
# In service_configs, keep only blockchain_node_1
"blockchain_node_1": {
    "name": "Blockchain Node",
    "command": ["python", "blockchain_node.py"],
    "port": 8546,
    ...
}
# Remove blockchain_node_2
```

This provides a cleaner, more realistic demo environment! 