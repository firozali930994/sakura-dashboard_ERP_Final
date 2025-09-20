# 🍃 Sakura ERP System

A complete Enterprise Resource Planning system with user management, role-based access control, and multi-language support.

## 🌟 Features

- **User Authentication**: Signup, Login, JWT-based auth
- **Role Management**: Admin, Staff roles with different permissions
- **Multi-language**: Arabic & English support
- **Profile Management**: Photo uploads, user profiles
- **Dashboard Analytics**: Real-time KPI calculations
- **Responsive Design**: Works on all devices

## 🚀 Live Demo

**Deployed on Railway**: [https://sakura-erp.railway.app](https://sakura-erp.railway.app)

## 🛠️ Tech Stack

- **Backend**: Node.js + Express
- **Database**: SQLite
- **Frontend**: HTML5 + Tailwind CSS + JavaScript
- **Authentication**: JWT + bcrypt
- **File Upload**: Multer
- **Hosting**: Railway

## 📱 Pages

- **Login**: `/login.html`
- **Signup**: `/signup.html` 
- **Main Dashboard**: `/index.html`
- **Admin Panel**: `/admin.html`
- **Accounts Payable**: `/payable.html`
- **Forecasting**: `/forecasting.html`

## 🔧 API Endpoints

- `POST /api/auth/login` - User login
- `POST /api/auth/signup` - User registration
- `GET /api/me` - Get user profile
- `PUT /api/me` - Update user profile
- `GET /api/users` - List users (admin only)
- `PUT /api/users/:id/role` - Update user role (admin only)

## 🌐 Deployment

This project is configured for Railway deployment with:
- Automatic builds
- Environment variables
- Database persistence
- File upload support

## 📝 License

MIT License - Feel free to use for your projects!

---

**Made with ❤️ for Sakura Company**
