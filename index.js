const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "chrono_explorer",
  timezone: "Z",
});

db.connect((err) => {
  if (err) {
    console.error("Erreur de connexion à MySQL:", err);
  } else {
    console.log("Connecté à la base de données chrono_explorer");
  }
});

// POST register
app.post("/auth/register", async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.query(
    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
    [username, email, hashedPassword],
    (err) => {
      if (err) res.status(500).send("Erreur serveur");
      else res.status(201).json({ message: "Utilisateur inscrit avec succès" });
    }
  );
});

// POST login
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) res.status(500).send("Erreur serveur");
      else if (results.length === 0)
        res.status(404).send("Utilisateur non trouvé");
      else {
        const user = results[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword)
          return res.status(401).send("Mot de passe incorrect");

        const token = jwt.sign({ id: user.id, role: user.role }, "SECRET_KEY", {
          expiresIn: "1h",
        });
        res.json({ token });
      }
    }
  );
});

// PUT update user
app.put("/auth/:id", async (req, res) => {
  const id = req.params.id;
  const { username, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    "UPDATE users SET username=?, email=?, password=? WHERE id=?",
    [username, email, hashedPassword, id],
    (err) => {
      if (err) res.status(500).send("Erreur serveur");
      else res.send("Utilisateur mis à jour");
    }
  );
});

// DELETE user
app.delete("/auth/:id", (req, res) => {
  const id = req.params.id;

  db.query("DELETE FROM users WHERE id = ?", [id], (err) => {
    if (err) res.status(500).send("Erreur serveur");
    else res.send("Utilisateur supprimé");
  });
});

const PORT = 4002;
app.listen(PORT, () => {
  console.log(`Auth Service démarré sur http://localhost:${PORT}`);
});
