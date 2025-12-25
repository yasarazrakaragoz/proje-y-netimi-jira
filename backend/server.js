const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// Demo kullanıcı listesi (RAM)
// Gerçek projede veritabanı olur
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
 * POST /api/register
 * body: { fullname, email, password }
 */
app.post("/api/register", async (req, res) => {
  const { fullname, email, password } = req.body;

  if (!fullname || !email || !password) {
    return res.status(400).json({
      error: "fullname, email ve password zorunludur"
    });
  }

  const exists = users.find(
    u => u.email.toLowerCase() === email.toLowerCase()
  );
  if (exists) {
    return res.status(409).json({
      error: "Bu e-posta zaten kayıtlı"
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      error: "Şifre en az 6 karakter olmalıdır"
    });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const newUser = {
    id: users.length + 1,
    fullname,
    email,
    passwordHash
  };
  users.push(newUser);

  const token = jwt.sign(
    { userId: newUser.id, email: newUser.email },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  return res.status(201).json({
    message: "Kayıt başarılı",
    user: {
      id: newUser.id,
      fullname: newUser.fullname,
      email: newUser.email
    },
    token
  });
});

// Sunucu
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Auth backend running on http://localhost:${PORT}`);
});
