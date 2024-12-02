// The AuthController manages:
// Registering a user (adding them to the database).
// Logging in a user (verifying credentials and returning access tokens).
// This controller uses:
// bcrypt for password encryption.
// jsonwebtoken (JWT) for creating secure tokens to identify users.
// MongoDB (via Mongoose) to interact with the database.
// a. registerUser: For User Registration
// What it does:
// Allows new users to create accounts by providing their details like username, password, and name.
// Flow:
// Check if all required fields (username, password, firstname, lastname) are provided.
// Hash the password using bcrypt to securely store it.
// Check if the username already exists.
// Save the user in the database.
// Generate a JWT token (a digital signature for secure communication).

import UserModel from "../models/userModel.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

// Register new user
export const registerUser = async (req, res) => {
  const { username, password, firstname, lastname } = req.body;

  // Check if all fields are provided
  if (!username || !password || !firstname || !lastname) {
    return res.status(400).json({ message: "All fields are required." });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPass = await bcrypt.hash(password, salt);
    req.body.password = hashedPass;
    const newUser = new UserModel(req.body);

    // Check if user already exists
    const oldUser = await UserModel.findOne({ username });
    if (oldUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Save new user
    const user = await newUser.save();
    //Generate a JWT token for the user
    const token = jwt.sign( 
      { username: user.username, id: user._id },
      process.env.JWTKEY,
      { expiresIn: "1h" }
    );
    res.status(200).json({ user, token });
  } catch (error) {
    console.error("Error during registration:", error.message);
    res.status(500).json({ message: "Server Error during registration" });
  }
};

// Login User
export const loginUser = async (req, res) => {
  const { username, password } = req.body;

  // Check if fields are missing
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required." });
  }

  try {
    const user = await UserModel.findOne({ username });

    if (!user) {
      return res.status(404).json("User not found");
    }

    // Compare the passwords
    const validity = await bcrypt.compare(password, user.password);
    if (!validity) {
      return res.status(400).json("Incorrect password");
    }

    const token = jwt.sign(
      { username: user.username, id: user._id },
      process.env.JWTKEY,
      { expiresIn: "1h" }
    );
    res.status(200).json({ user, token });
  } catch (err) {
    console.error("Error during login:", err.message);
    res.status(500).json({ message: "Server Error during login" });
  }
};
