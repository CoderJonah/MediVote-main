# MediVote Complete System Startup Guide

## 🚀 Manual Startup (Recommended)

This guide shows how to start each component individually for maximum reliability.

### Step 1: Kill Existing Processes
```powershell
taskkill /F /IM python.exe
```

### Step 2: Start Backend API
```powershell
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
```
**Expected output:** `INFO: Uvicorn running on http://0.0.0.0:8001`

### Step 3: Start Frontend Server
Open a **new PowerShell window** and run:
```powershell
python -m http.server 8080 --directory frontend
```
**Expected output:** `Serving HTTP on :: port 8080`

### Step 4: Start Blockchain Node
Open a **new PowerShell window** and run:
```powershell
python blockchain_node.py --port 8081 --data-dir blockchain_data
```
**Expected output:** `✅ Blockchain node started successfully!`

### Step 5: Start Incentive System
Open a **new PowerShell window** and run:
```powershell
python node_incentive_system.py --port 8082
```
**Expected output:** `Incentive system started on http://0.0.0.0:8082`

### Step 6: Start Network Coordinator
Open a **new PowerShell window** and run:
```powershell
python network_coordinator.py --port 8083
```
**Expected output:** `Network coordinator started on port 8083`

### Step 7: Start Network Dashboard
Open a **new PowerShell window** and run:
```powershell
python network_dashboard.py --port 8084
```
**Expected output:** `Network dashboard started on port 8084`

## 🌐 Access URLs

Once all services are running:

- **Frontend:** http://localhost:8080
- **Backend API:** http://localhost:8001
- **Blockchain:** http://localhost:8081
- **Incentive System:** http://localhost:8082
- **Network Coordinator:** http://localhost:8083
- **Network Dashboard:** http://localhost:8084

## 🧪 Test System

Run this to verify all components:
```powershell
python test_system.py
```

## 🛑 Stop All Services

Press `Ctrl+C` in each PowerShell window to stop the services.

## 📋 Quick Commands

### Start All Services (Automated - Less Reliable)
```powershell
python start_medivote_complete.py
```

### Start Core Services Only
```powershell
python start_medivote_final.py
```

### Test System Status
```powershell
python test_system.py
```

## 🔧 Troubleshooting

### If services fail to start:
1. Make sure no other Python processes are running
2. Check if ports are already in use
3. Try starting services one by one
4. Check the logs for error messages

### If you see "port already in use":
```powershell
netstat -ano | findstr :8001
```
Then kill the process using the PID shown.

### If backend fails to start:
```powershell
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8001 --reload
```

## 🎯 System Features

- **Decentralized blockchain voting**
- **Node incentive system**
- **Real-time network monitoring**
- **Advanced cryptographic security**
- **End-to-end verifiability**

## 📝 Usage

1. Open http://localhost:8080 in your browser
2. Register as a voter
3. Run a blockchain node to create ballots
4. Cast your vote securely
5. Monitor the network at http://localhost:8084 