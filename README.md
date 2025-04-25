# User Management System

## Introduction

The User Management System is a full-stack application developed using Node.js (backend) and Angular (frontend). It enables the management of user accounts with features such as email sign-up, verification, JWT authentication, role-based authorization, password reset functionality, and profile management. Admin users have access to a dashboard for managing all accounts. The system also implements a fake backend to allow for frontend development without a real backend during the initial stages.

### Key Features:

- **Backend (Node.js + MySQL)**:
  - Email sign-up and verification
  - JWT authentication with refresh tokens
  - Role-based authorization (Admin and User roles)
  - Forgot password and reset password functionality
  - CRUD operations for managing accounts (restricted to Admin users)
- **Frontend (Angular 10/17)**:
  - Email sign-up and verification
  - JWT authentication with refresh tokens
  - Role-based authorization (Admin and User roles)
  - Forgot password and reset password functionality
  - Profile management (view and update profile)
  - Admin dashboard for managing all accounts (restricted to Admin role)
  - Fake backend implementation for backend-less development and testing

## Installation Instructions

1. **Clone the repository**:

   ```bash
   git clone https://github.com/your-username/user-management-system.git
   ```

2. **Install dependencies**:

   ```bash
   npm install
   ```

3. **Start the backend server**:

   ```bash
   npm start
   ```

4. **Start the Angular app**:
   ```bash
   ng serve
   ```

## Usage

1. **Register a new account**:  
   Visit `/accounts/register` to create a new account.

2. **Verify your email**:  
   After registration, check your inbox for a verification link.

3. **Log in**:  
   Visit `/accounts/login` to log in with your registered credentials.

4. **Manage your profile**:  
   Once logged in, you can view and update your profile.

5. **Admin dashboard** (Admin users only):  
   Admin users can access the dashboard to manage all user accounts.

## Testing

### Functional Testing:

- The following user flows have been tested:
  - Registration and email verification
  - Login and authentication

## License

MIT License

---
