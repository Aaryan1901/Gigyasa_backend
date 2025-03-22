require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

// Initialize Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

const app = express();

// Enable CORS for your frontend origin
app.use(cors({
  origin: "https://jigyasa2025.vercel.app", // Replace with your frontend URL
  credentials: true, // Allow cookies and credentials
}));

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

// Log environment variables for debugging
console.log("Server is starting...");
console.log("Supabase URL:", process.env.SUPABASE_URL);
console.log("JWT Secret:", process.env.JWT_SECRET ? "Set" : "Not Set");

// Root route
app.get("/", (req, res) => {
  res.send("Backend is running successfully!");
});

// User Registration
app.post("/register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  // Check if all fields are provided
  if (!name || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: "All fields are required" });
  }

  // Check if passwords match
  if (password !== confirmPassword) {
    return res.status(400).json({ error: "Passwords do not match" });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Insert into Supabase
  const { data, error } = await supabase
    .from("users")
    .insert([{ name, email, password: hashedPassword }]);

  if (error) {
    console.error("Registration error:", error);
    return res.status(400).json({ error: error.message });
  }

  res.json({ message: "User registered successfully!" });
});

// User Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Fetch user from Supabase
  const { data, error } = await supabase
    .from("users")
    .select("*")
    .eq("email", email.toLowerCase())
    .single();

  if (error || !data) {
    console.error("Login error:", error);
    return res.status(400).json({ error: "User not found" });
  }

  // Compare passwords
  const validPassword = await bcrypt.compare(password, data.password);
  if (!validPassword) {
    return res.status(400).json({ error: "Invalid credentials" });
  }

  // Generate JWT token
  const token = jwt.sign({ id: data.id, email: data.email, name: data.name }, JWT_SECRET, { expiresIn: "1h" });

  res.json({ token });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));