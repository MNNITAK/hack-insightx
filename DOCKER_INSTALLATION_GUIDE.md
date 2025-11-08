# 🐳 Docker Desktop Installation Guide for Virtual Cybersecurity Sandbox

## Prerequisites Check
Before installing Docker Desktop, ensure your system meets these requirements:

### System Requirements
- **Windows 10/11**: Version 1903 or later (Build 18362+)
- **WSL 2**: Windows Subsystem for Linux version 2
- **Hyper-V**: Enabled (or WSL 2 backend)
- **Virtualization**: Enabled in BIOS
- **RAM**: Minimum 4GB (8GB+ recommended)
- **Storage**: At least 4GB free space

## 🚀 Installation Steps

### Step 1: Enable WSL 2 (Required)
Open PowerShell as Administrator and run:

```powershell
# Enable Windows Subsystem for Linux
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart

# Enable Virtual Machine Platform
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

# Restart your computer
Restart-Computer
```

After restart, set WSL 2 as default:
```powershell
wsl --set-default-version 2
```

### Step 2: Download Docker Desktop
1. Go to https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe
2. Download Docker Desktop Installer.exe
3. Or use this direct PowerShell command:

```powershell
$url = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
$output = "$env:USERPROFILE\Downloads\DockerDesktopInstaller.exe"
Invoke-WebRequest -Uri $url -OutFile $output
Write-Host "✅ Downloaded to: $output"
```

### Step 3: Install Docker Desktop
1. Run the installer as Administrator
2. During installation, ensure these options are checked:
   - ✅ Enable WSL 2 based engine
   - ✅ Add shortcut to desktop
3. Complete the installation and restart when prompted

### Step 4: Verify Installation
After restart, open PowerShell and verify:

```powershell
# Check Docker version
docker --version

# Check Docker Compose version  
docker-compose --version

# Test Docker installation
docker run hello-world
```

## 🔧 Post-Installation Configuration

### Configure Docker Resources
1. Open Docker Desktop
2. Go to Settings → Resources → Advanced
3. Set recommended values:
   - **CPUs**: 4 or more
   - **Memory**: 8GB or more 
   - **Swap**: 2GB
   - **Disk image size**: 64GB

### Enable Kubernetes (Optional)
1. Go to Settings → Kubernetes
2. Check "Enable Kubernetes"
3. Apply & restart

## 🐍 Python Dependencies Installation

### Install Virtual Cybersecurity Sandbox Dependencies
```powershell
# Navigate to sandbox directory
cd C:\Users\ay912\Desktop\DEVELOPMENT\WEB\HACK36\INSIGHTX-hack36\backend\sandbox

# Install Python requirements
pip install -r requirements.txt

# If pip is not available, use py -m pip:
py -m pip install -r requirements.txt
```

## 🌐 Frontend Dependencies

### Install Three.js for 3D Visualization
```powershell
# Navigate to frontend directory
cd C:\Users\ay912\Desktop\DEVELOPMENT\WEB\HACK36\INSIGHTX-hack36\client\src\my-next-app

# Install Three.js
npm install three @types/three

# Install additional visualization libraries
npm install @react-three/fiber @react-three/drei
```

## 🎯 Testing Installation

### Test Docker Functionality
```powershell
# Test basic Docker commands
docker version
docker info
docker images
docker ps

# Test container creation
docker run --rm alpine echo "Docker is working!"
```

### Test Virtual Sandbox Backend
```powershell
# Navigate to backend
cd C:\Users\ay912\Desktop\DEVELOPMENT\WEB\HACK36\INSIGHTX-hack36\backend\api

# Test sandbox imports
py -c "
import sys, os
sys.path.append('../sandbox')
try:
    from sandbox.container_orchestrator import RuleBasedContainerOrchestrator
    from sandbox.attack_simulator import RuleBasedAttackSimulator  
    from sandbox.defense_agent import RuleBasedDefenseAgent
    print('✅ All Virtual Cybersecurity Sandbox modules loaded successfully!')
except Exception as e:
    print(f'❌ Error: {e}')
"

# Start the backend server
py security_agent.py
```

### Test Frontend with Sandbox
```powershell
# Navigate to frontend
cd C:\Users\ay912\Desktop\DEVELOPMENT\WEB\HACK36\INSIGHTX-hack36\client\src\my-next-app

# Start development server
npm run dev
```

## 🚨 Troubleshooting Common Issues

### Issue 1: WSL 2 Installation Failed
**Solution:**
1. Check Windows version: `winver`
2. Update Windows to latest version
3. Enable virtualization in BIOS
4. Run Windows Update

### Issue 2: Docker Desktop Won't Start
**Solution:**
1. Restart Docker Desktop service:
   ```powershell
   net stop com.docker.service
   net start com.docker.service
   ```
2. Check Windows Features:
   - Windows Subsystem for Linux ✅
   - Virtual Machine Platform ✅
   - Hyper-V ✅

### Issue 3: Container Creation Fails
**Solution:**
1. Check Docker daemon is running: `docker info`
2. Restart Docker Desktop application
3. Check available disk space
4. Reset Docker to factory defaults if needed

### Issue 4: Permission Denied Errors
**Solution:**
1. Run PowerShell as Administrator
2. Add your user to docker-users group:
   ```powershell
   net localgroup docker-users $env:USERNAME /add
   ```
3. Log out and log back in

### Issue 5: Python Dependencies Fail
**Solution:**
1. Upgrade pip: `py -m pip install --upgrade pip`
2. Install Visual C++ Build Tools if needed
3. Use conda instead of pip if available

## 🎉 Verification Checklist

Before running the Virtual Cybersecurity Sandbox:

- [ ] Docker Desktop installed and running
- [ ] WSL 2 enabled and configured  
- [ ] Python dependencies installed
- [ ] Three.js installed for frontend
- [ ] Backend imports working
- [ ] Frontend builds successfully
- [ ] Can create and run Docker containers

## 🚀 Ready to Launch!

Once all items are checked, you can:

1. Start the backend: `py security_agent.py` 
2. Start the frontend: `npm run dev`
3. Open InsightX at http://localhost:3000
4. Click the "🚀 Virtual Sandbox" button
5. Deploy your first live architecture!

## 🆘 Need Help?

If you encounter issues:
1. Check Docker Desktop logs in the application
2. Review Windows Event Viewer for system errors
3. Ensure all Windows updates are installed
4. Consider using Docker Toolbox as fallback on older systems

**Happy containerizing! 🐳**