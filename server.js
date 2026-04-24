require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');

const { initServerKeys, getServerECCPublicKey } = require('./config/crypto');
const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 3000;

console.log('\n╔════════════════════════════════════════╗');
console.log('║  CIFRADO HÍBRIDO + ECC E2EE — Node.js ║');
console.log('╚════════════════════════════════════════╝\n');
initServerKeys();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 }
}));

// Endpoint para que el frontend obtenga la clave pública ECC del servidor
app.get('/api/server-public-key', (req, res) => {
  res.json({ eccPublicKey: getServerECCPublicKey() });
});

app.use('/', authRoutes);

app.listen(PORT, () => {
  console.log(`   Servidor: http://localhost:${PORT}`);
  console.log(`   Login:    http://localhost:${PORT}/login`);
  console.log(`   Registro: http://localhost:${PORT}/register\n`);
});
