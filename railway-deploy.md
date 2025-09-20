# 🚀 Sakura ERP - Railway Deployment Guide

## Quick Deploy Steps:

### 1. Create GitHub Repository
```bash
git init
git add .
git commit -m "Initial Sakura ERP"
git remote add origin https://github.com/YOUR_USERNAME/sakura-erp.git
git push -u origin main
```

### 2. Deploy on Railway
1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub
3. Click "New Project"
4. Select "Deploy from GitHub repo"
5. Choose your repository
6. Railway will auto-detect and deploy!

### 3. Environment Variables (Auto-set)
- `PORT`: 3000 (auto-set by Railway)
- `NODE_ENV`: production

### 4. Access Your App
- Frontend: `https://YOUR_PROJECT_NAME.railway.app`
- Backend API: `https://YOUR_PROJECT_NAME.railway.app/api`

## Auto-Update System
- Push to GitHub → Automatic deployment
- No manual intervention needed!

## File Structure
```
├── backend/          # Node.js backend
├── SakuraPortal/     # Frontend files
├── railway.json      # Railway config
├── nixpacks.toml     # Build config
└── railway-deploy.md # This guide
```

## Support
- Railway Dashboard: Monitor your app
- Logs: Real-time application logs
- Metrics: Performance monitoring
