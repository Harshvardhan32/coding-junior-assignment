# Node.js Backend Application

This is a simple backend application built with Node.js, Express.js, and MongoDB. The application allows users to register and log in securely, with passwords hashed before being stored in the database. A JSON Web Token (JWT) is issued upon successful login for authentication.

---

## Features

- User Registration with Name, Email, and Password
- Password Hashing for Security
- User Login with JWT Authentication
- Environment Variable Support for Sensitive Data
- Error Handling for Missing Fields and Incorrect Credentials

---

## Prerequisites

Before you begin, ensure you have the following installed:

- [Node.js](https://nodejs.org/) (v16 or higher)
- [MongoDB](https://www.mongodb.com/) (local or hosted)
- [npm](https://www.npmjs.com/) (comes with Node.js)

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Harshvardhan32/coding-junior-assignment.git
   cd coding-junior-assignment

2. **Install dependencies**:
   ```bash
   npm install

3. **Set up environment variables**:
   ```bash
   PORT = port_number
   MONGO_URL = 'mongodb_url'
   JWT_SECRET = 'your_jwt_secret'
   
1. **Start the server**:
   ```bash
   npm start
