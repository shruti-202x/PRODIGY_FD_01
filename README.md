# PRODIGY_FD_01
secure user authentication
1. Architecture Overview
We'll consider a typical full-stack architecture where:

Frontend: React.js (or any modern frontend framework)

Backend: Node.js with Express.js (or any backend framework)

Database: MongoDB (or any SQL/NoSQL database)

Authentication Method: JWT (JSON Web Tokens) with hashed passwords

2. Frontend (React.js Example)
Login/Signup Forms: Users will enter their credentials.

State Management: Store the JWT token in memory or local storage (using context API or Redux).

Axios: To send requests to the backend.

Frontend Steps:
Signup (POST request to /auth/signup):

Send a POST request with user details (username, email, password).

Receive a JWT token (if successful) and store it.

Login (POST request to /auth/login):

Send the credentials (username/email & password).

On success, store the received JWT token.

Token Storage:

Local Storage or Cookies (with HttpOnly flag for extra security).

Use the token for subsequent requests to access protected routes.

Example (React Login Component):
javascript
Copy
Edit
import React, { useState } from 'react';
import axios from 'axios';

const Login = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const response = await axios.post('http://localhost:5000/auth/login', { email, password });
            localStorage.setItem('token', response.data.token); // Store JWT
            alert('Logged in successfully');
        } catch (error) {
            console.error('Login failed:', error);
            alert('Invalid credentials');
        }
    };

    return (
        <form onSubmit={handleSubmit}>
            <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
            />
            <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
            />
            <button type="submit">Login</button>
        </form>
    );
};

export default Login;
3. Backend (Node.js + Express)
The backend will handle the following:

User Registration: Hash the password before saving to the database.

Login: Compare the password with the hashed password and generate a JWT token.

Protected Routes: Ensure routes are protected by validating the JWT token sent in headers.

Backend Steps:
Install Dependencies:

bash
Copy
Edit
npm install express bcryptjs jsonwebtoken dotenv mongoose
User Model (MongoDB schema for user registration):

javascript
Copy
Edit
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

module.exports = User;
Hashing Passwords (using bcryptjs):

Pre-save Middleware: Before saving a user, hash their password.

javascript
Copy
Edit
const bcrypt = require('bcryptjs');
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});
JWT Generation (using jsonwebtoken):

Create a function to generate a JWT token after successful login.

javascript
Copy
Edit
const jwt = require('jsonwebtoken');

const generateToken = (userId) => {
    return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
        expiresIn: '1h', // Token expiry time
    });
};
Authentication Routes:

Signup Route: Create a new user and hash the password.

Login Route: Validate the credentials and generate a JWT.

javascript
Copy
Edit
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const router = express.Router();

// Signup route
router.post('/signup', async (req, res) => {
    const { email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const newUser = new User({ email, password });
        await newUser.save();
        const token = generateToken(newUser._id);
        res.status(201).json({ token });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Login route
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = generateToken(user._id);
        res.json({ token });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Token Verification Middleware
const protect = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

module.exports = { router, protect };
Server Setup (app.js):

javascript
Copy
Edit
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const { router } = require('./authRoutes');

dotenv.config();
const app = express();

app.use(express.json());
app.use('/auth', router);

mongoose.connect(process.env.DB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Database connected'))
    .catch((err) => console.error(err));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
4. Protected Routes
To protect any route, you just need to apply the protect middleware.

Example:
javascript
Copy
Edit
const { protect } = require('./authRoutes');

app.get('/protected', protect, (req, res) => {
    res.send('This is a protected route');
});
5. Secure Authentication Best Practices
Hashing Passwords: Never store plaintext passwords. Always hash them using bcrypt or argon2.

JWT Expiry: Set an expiration time for JWT tokens and handle refresh tokens if necessary.

Token Storage: Use httpOnly cookies for storing tokens to avoid XSS attacks.

Token Verification: Always verify the JWT on every protected request.

Use HTTPS: Ensure your application uses HTTPS in production to encrypt data in transit.

6. Extra Security Considerations
CSRF Protection: If you’re using cookies for JWT, you’ll need to handle CSRF (Cross-Site Request Forgery).

Two-Factor Authentication: For extra security, implement 2FA (e.g., Google Authenticator).

Rate Limiting: Prevent brute-force attacks by implementing rate limiting on login routes.

Session Expiry: If you're using sessions, set a reasonable expiry time for user sessions.

This setup should give you a secure authentication system. Let me know if you want more details on any part or if you need help with a specific technology!



