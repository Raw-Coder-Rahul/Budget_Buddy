const User = require('../models/User');
const jwt = require('jsonwebtoken');

// Generate JWT Token
const generateToken = (id) => {
    try {
        return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    } catch (err) {
        console.error("JWT generation error:", err.message);
        throw err;
    }
};

// Register User
exports.registerUser = async (req, res) => {
    const { fullName, email, password, profileImageUrl } = req.body;

    // Validation : Check for missing fields
    if (!fullName || !email || !password) {
        return res.status(400).json({ message: "All fields are required "});
    }

    try {
        // Check if email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "Email already in use" });
        }

        // Create the user
        const user = await User.create({
            fullName,
            email,
            password,
            profileImageUrl,
        });

        res.status(201).json({
            id: user._id,
            user,
            token: generateToken(user._id),
        });
    } catch (err) {
        res
            .status(500)
            .json({ message: "Error registering user", error: err.message });
    }
};

// Login User
exports.loginUser = async (req, res) => {
    const { email, password } = req.body;
    if ( !email || !password ){
        return res.status(400).json({ message: "All fields are required" });
    }
    try {
        const user = await User.findOne({ email });
        if (!user || !(await user.comparePassword(password))) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        res.status(200).json({
            id: user._id,
            user,
            token: generateToken(user._id),
        });
    } catch (err) {
        res
            .status(500)
            .json({ message: "Error registering user", error: err.message });
    }
};

// Get User Info
exports.getUserInfo = async (req, res) => {
    // Validate if the user is authenticated
    if (!req.user || !req.user.id) {
        return res.status(401).json({ message: "Unauthorized: No user information provided" });
    }

    try {
        const user = await User.findById(req.user.id).select("fullName email profileImageUrl createdAt");
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json(user);
    } catch (err) {
        console.error("Error fetching user information:", err);
        res.status(500).json({ message: "Error fetching user information", error: err.message });
    }
};
