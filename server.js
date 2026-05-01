require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const admin = require("firebase-admin");

const app = express();
app.use(bodyParser.json());
app.use(express.static(__dirname));

// Firebase init
admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_CONFIG))
});
const db = admin.firestore();

// JWT Middleware
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.sendStatus(401);

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
}

// SMTP
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Student signup
app.post("/signup-student", async (req, res) => {
  const { email, password } = req.body;

  await db.collection("students").add({ email, password });
  res.send("Student created");
});

// Student login
app.post("/login-student", async (req, res) => {
  const { email, password } = req.body;

  const snap = await db.collection("students")
    .where("email", "==", email)
    .where("password", "==", password)
    .get();

  if (snap.empty) return res.sendStatus(401);

  const token = jwt.sign({ email }, process.env.JWT_SECRET);
  res.json({ token });
});

// Parent signup
app.post("/signup-parent", async (req, res) => {
  const { email, password } = req.body;

  await db.collection("parents").add({ email, password });
  res.send("Parent created");
});

// Parent login
app.post("/login-parent", async (req, res) => {
  const { email, password } = req.body;

  const snap = await db.collection("parents")
    .where("email", "==", email)
    .where("password", "==", password)
    .get();

  if (snap.empty) return res.sendStatus(401);

  const token = jwt.sign({ email }, process.env.JWT_SECRET);
  res.json({ token });
});

// Admin login
app.post("/admin-login", (req, res) => {
  const { user, pass } = req.body;

  if (
    user === process.env.ADMIN_USER &&
    pass === process.env.ADMIN_PASS
  ) {
    const token = jwt.sign({ role: "admin" }, process.env.JWT_SECRET);
    return res.json({ token });
  }

  res.sendStatus(401);
});

// Attendance
app.post("/attendance", auth, async (req, res) => {
  const { student, status } = req.body;

  await db.collection("attendance").add({
    student,
    status,
    date: new Date()
  });

  // notify parent
  await transporter.sendMail({
    from: process.env.SMTP_USER,
    to: "parent@email.com",
    subject: "Attendance Update",
    text: `${student} is ${status}`
  });

  res.send("Saved");
});

app.listen(3000, () => console.log("Server running"));
