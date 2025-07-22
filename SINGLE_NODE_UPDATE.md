# MediVote Service Manager - Single Blockchain Node Update

## Changes Made

### 1. **Removed Second Blockchain Node**
- Removed `blockchain_node_2` from service configurations
- Now only runs a single blockchain node on port 8546
- Cleaner and more resource-efficient setup

### 2. **Updated Configuration**
- Single node configuration with no bootstrap peers
- Uses `./blockchain_data` directory (not numbered)
- More realistic for demo/development environment

### 3. **Benefits of Single Node Setup**

#### For Development:
- ✅ **Less Resource Usage**: Only one blockchain process
- ✅ **No Port Conflicts**: No fighting over ports 8546/8547
- ✅ **Simpler Testing**: Easier to debug and monitor
- ✅ **Faster Startup**: One less service to initialize

#### For Production:
- Run nodes on **separate physical machines**
- Each organization runs their **own node**
- True decentralization and fault tolerance

## Updated Service Count

Now running **6 services** instead of 7:
1. Backend API (port 8001)
2. Blockchain Node (port 8546)
3. Frontend (port 8080)
4. Incentive System (port 8082)
5. Network Coordinator (port 8083)
6. Network Dashboard (port 8084)

## Testing the Update

1. Stop all services
2. Restart the service manager
3. All services should start successfully
4. Blockchain node accessible at http://localhost:8546

## Future Expansion

When ready for a distributed network:
- Deploy nodes to separate servers
- Update bootstrap nodes in configuration
- Enable peer discovery across network 