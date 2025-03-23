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

  // Check if the email already exists
  const { data: existingUser, error: fetchError } = await supabase
    .from("users")
    .select("*")
    .eq("email", email.toLowerCase())
    .single();

  if (fetchError && fetchError.code !== "PGRST116") { // PGRST116 is the code for "No rows found"
    console.error("Error checking existing user:", fetchError);
    return res.status(500).json({ error: "An error occurred while checking the email" });
  }

  if (existingUser) {
    return res.status(400).json({ error: "Email already exists" });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Insert into Supabase
  const { data, error } = await supabase
    .from("users")
    .insert([{ name, email, password: hashedPassword }])
    .select(); // Add .select() to return the inserted data

  if (error) {
    console.error("Registration error:", error);
    return res.status(400).json({ error: error.message });
  }

  // Return the inserted user data
  res.json({ message: "User registered successfully!", user: data[0] });
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

  res.json({ token, name: data.name, email: data.email, id: data.id });
});

// Fetch user details
app.get("/user", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { data, error } = await supabase
      .from("users")
      .select("*")
      .eq("id", decoded.id)
      .single();

    if (error || !data) {
      return res.status(400).json({ error: "User not found" });
    }

    res.json({ id: data.id, name: data.name, email: data.email });
  } catch (error) {
    res.status(401).json({ error: "Invalid token" });
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));