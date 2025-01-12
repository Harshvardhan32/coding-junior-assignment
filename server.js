// Import required modules
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

// Import User Model
const User = require("./models/User");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());

const dbConnect = async () => {
    try {
        mongoose.connect(process.env.MONGO_URL);
        console.log("Database connected successfully.");
    } catch (error) {
        console.log("Database connection failed: ", error.message);
    }
}

// Database connection
dbConnect();

// Registration route
app.post("/api/register", async (req, res) => {
    try {
        // Destructure all the fields from the req body
        const { name, email, password } = req.body;

        // Validate input fields
        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required."
            });
        }

        // Check if the user already exists
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: "Email is already registered. Please login to continue."
            });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = await User.create({
            name,
            email,
            password: hashedPassword
        });

        // Return successfull response
        return res.status(200).json({
            success: true,
            data: newUser,
            message: "User registered successfully."
        });
    } catch (err) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error."
        });
    }
});

// Login route
app.post("/api/login", async (req, res) => {
    try {
        // Destructure all the fields from the req body
        const { email, password } = req.body;

        // Validate input fields
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required."
            });
        }

        // Check if the user exists
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid email."
            });
        }

        // Compare the provided password with the hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(400).json({
                success: false,
                message: "Invalid password."
            });
        }

        // Generate a JWT token
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, {
            expiresIn: "1h",
        });

        // return successfull response
        return res.status(200).json({
            success: true,
            token: token,
            message: "Login successfully.",
        });
    } catch (err) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error."
        });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});