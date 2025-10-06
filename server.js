const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios"); // ✅ Used for proxy
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || "*", 
  credentials: true
}));
app.use(express.json());

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err);
  } else {
    console.log("✅ Connected to MySQL database");
  }
});

// ---------- Test Route ----------
app.get("/", (req, res) => {
  res.send("Urban Plus Backend Running 🚀");
});

// ---------- Sign Up Route ----------
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ msg: "Name, email, and password are required" });
  }
  if (password.length < 6) {
    return res.status(400).json({ msg: "Password must be at least 6 characters" });
  }

  try {
    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
      if (err) return res.status(500).json({ msg: "Database error", err });
      if (result.length > 0) return res.status(400).json({ msg: "Email already registered" });

      const hashedPassword = await bcrypt.hash(password, 10);

      db.query(
        "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
        [name, email, hashedPassword],
        (err2, result2) => {
          if (err2) return res.status(500).json({ msg: "Database error", err2 });
          return res.status(201).json({ msg: "User registered successfully" });
        }
      );
    });
  } catch (error) {
    return res.status(500).json({ msg: "Server error", error });
  }
});

// ---------- Login Route ----------
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ msg: "Email and password are required" });
  }

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (err) return res.status(500).json({ msg: "Database error", err });
    if (result.length === 0) return res.status(400).json({ msg: "Invalid email or password" });

    const user = result[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ msg: "Invalid email or password" });

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      msg: "Login successful",
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  });
});

// ---------- Middleware to protect routes ----------
function verifyToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1]; // Bearer token
  if (!token) return res.status(401).json({ msg: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ msg: "Invalid token" });
    req.user = decoded;
    next();
  });
}

// ---------- Protected Profile Route ----------
app.get("/api/auth/me", verifyToken, (req, res) => {
  res.status(200).json({
    msg: "User profile data",
    user: req.user,
  });
});

// ---------- Save City for User ----------
app.post("/api/user/add-city", verifyToken, (req, res) => {
  const { city } = req.body;
  const userId = req.user.id;

  if (!city) return res.status(400).json({ msg: "City name is required" });

  const query = "INSERT INTO user_cities (user_id, city_name) VALUES (?, ?)";
  db.query(query, [userId, city], (err, result) => {
    if (err) return res.status(500).json({ msg: "Database error", err });
    res.json({ msg: "City saved successfully" });
  });
});

// ---------- Get User Cities ----------
app.get("/api/user/cities", verifyToken, (req, res) => {
  const userId = req.user.id;

  const query = "SELECT city_name FROM user_cities WHERE user_id = ?";
  db.query(query, [userId], (err, results) => {
    if (err) return res.status(500).json({ msg: "Database error", err });
    res.json(results.map(r => r.city_name));
  });
});

// ---------- Delete City for User ----------
app.delete("/api/user/delete-city", verifyToken, (req, res) => {
  const { city } = req.body;
  const userId = req.user.id;

  if (!city) return res.status(400).json({ msg: "City name is required" });

  const query = "DELETE FROM user_cities WHERE user_id = ? AND city_name = ?";
  db.query(query, [userId, city], (err, result) => {
    if (err) return res.status(500).json({ msg: "Database error", err });
    if (result.affectedRows === 0) {
      return res.status(404).json({ msg: "City not found or not owned by user" });
    }
    res.json({ msg: "City deleted successfully" });
  });
});

// ---------- ✅ NEWS PROXY ROUTE (City-based fix for CORS issue) ----------
app.get("/api/news", async (req, res) => {
  try {
    const { city = "India" } = req.query;
    const url = `https://newsapi.org/v2/everything?q=${encodeURIComponent(city)}&language=en&pageSize=10&sortBy=publishedAt&apiKey=${process.env.NEWS_API_KEY}`;
    const response = await axios.get(url);
    res.json(response.data);
  } catch (error) {
    console.error("❌ News API error:", error.message);
    res.status(500).json({ msg: "Error fetching news" });
  }
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
