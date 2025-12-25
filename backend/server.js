const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// Demo kullanıcı listesi (RAM)
const users = []; // { id, fullname, email, passwordHash }

const JWT_SECRET = "dev-secret-key";

/**
 * Sağlık kontrolü
 */
app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "auth-backend" });
});

/**
 * PROJ-5: Kullanıcı Kayıt API
 */
app.post("/api/register", async (req, res) => {
  const { fullname, email, password } = req.body;

  if (!fullname || !email || !password) {
    return res.status(400).json({ error: "Alanlar zorunludur" });
  }

  const exists = users.find(u => u.email === email);
  if (exists) {
    return res.status(409).json({ error: "E-posta zaten kayıtlı" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  users.push({
    id: users.length + 1,
    fullname,
    email,
    passwordHash
  });

  return res.status(201).json({ message: "Kayıt başarılı" });
});

/**
 * PROJ-6: Kullanıcı Giriş API
 */
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({ error: "Hatalı giriş" });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: "Hatalı giriş" });
  }

  const token = jwt.sign(
    { userId: user.id },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ message: "Giriş başarılı", token });
});

/**
 * PROJ-7: Şifre Sıfırlama API
 */
app.post("/api/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(404).json({ error: "Kullanıcı bulunamadı" });
  }

  user.passwordHash = await bcrypt.hash(newPassword, 10);
  res.json({ message: "Şifre güncellendi" });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
