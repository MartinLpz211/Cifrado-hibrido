const bcrypt = require('bcryptjs');
const db = require('../config/db');
const {
  cifradoHibrido, descifradoHibrido,
  getServerRSAPublicKey, generarClavesECC,
  descifrarPayloadECC
} = require('../config/crypto');

exports.getRegister = (req, res) => res.render('register', { error: null, success: null });

exports.postRegister = async (req, res) => {
  const { nombre, email, password, confirmPassword } = req.body;

  if (!nombre || !email || !password || password !== confirmPassword)
    return res.render('register', { error: 'Datos inválidos', success: null });

  try {
    const [existing] = await db.query('SELECT id FROM usuarios WHERE email = ?', [email]);
    if (existing.length > 0)
      return res.render('register', { error: 'Email ya registrado', success: null });

    console.log('[REGISTRO] Procesando:', email);
    const passwordHash = await bcrypt.hash(password, 12);
    const { publicKeyHex, privKeyEncrypted } = generarClavesECC(password);

    await db.query(
      'INSERT INTO usuarios (nombre, email, password_hash, ecc_public_key, ecc_private_key_enc) VALUES (?, ?, ?, ?, ?)',
      [nombre, email, passwordHash, publicKeyHex, privKeyEncrypted]
    );

    console.log('[REGISTRO] Usuario guardado ✓');
    return res.render('register', { error: null, success: 'Registrado. Ve a login.' });

  } catch (err) {
    console.error('[ERROR]', err.message);
    res.render('register', { error: 'Error en servidor', success: null });
  }
};

exports.getLogin = (req, res) => res.render('login');

// POST /login — recibe el payload ya cifrado con ECC desde el frontend
exports.postLogin = async (req, res) => {
  // req.body contiene: { eccPayload, eccClientPublicKey }
  // El frontend cifró { email, password } con ECC antes de enviar
  const { eccPayload, eccClientPublicKey } = req.body;

  if (!eccPayload || !eccClientPublicKey)
    return res.status(400).json({ ok: false, error: 'Payload cifrado requerido' });

  console.log('\n[LOGIN] Payload ECC cifrado recibido del frontend');
  console.log('[LOGIN] Tamaño payload:', eccPayload.data.length, 'chars');

  let credentials;
  try {
    // ── DESCIFRAR PAYLOAD ECC (Cifrado a Nivel de Aplicación) ─────────────────
    credentials = descifrarPayloadECC(eccPayload, eccClientPublicKey);
  } catch (err) {
    console.error('[ERROR] Fallo al descifrar ECC:', err.message);
    return res.status(400).json({ ok: false, error: 'Payload inválido' });
  }

  const { email, password } = credentials;

  try {
    const [rows] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);

    if (rows.length === 0) {
      await db.query('INSERT INTO login_logs (email, exitoso, cifrado_usado) VALUES (?, false, ?)',
        [email, 'ECC-P256 + RSA-2048 + AES-256-CBC']);
      return res.status(401).json({ ok: false, error: 'Credenciales inválidas' });
    }

    const usuario = rows[0];
    const passwordValido = await bcrypt.compare(password, usuario.password_hash);

    if (!passwordValido) {
      await db.query('INSERT INTO login_logs (usuario_id, email, exitoso, cifrado_usado) VALUES (?, ?, false, ?)',
        [usuario.id, email, 'ECC-P256 + RSA-2048 + AES-256-CBC']);
      return res.status(401).json({ ok: false, error: 'Credenciales inválidas' });
    }

    // ── CIFRADO HÍBRIDO para el token de sesión ────────────────────────────────
    const tokenPayload = JSON.stringify({ userId: usuario.id, email: usuario.email, ts: Date.now() });
    const paquete = cifradoHibrido(tokenPayload, getServerRSAPublicKey());
    descifradoHibrido(paquete); // verificación interna

    // Log y sesión
    await db.query(
      'INSERT INTO login_logs (usuario_id, email, exitoso, ip_address, cifrado_usado) VALUES (?, ?, true, ?, ?)',
      [usuario.id, email, req.ip, 'ECC-P256 + RSA-2048 + AES-256-CBC']
    );
    await db.query('UPDATE usuarios SET last_login = NOW() WHERE id = ?', [usuario.id]);

    req.session.userId   = usuario.id;
    req.session.userName = usuario.nombre;
    req.session.loggedIn = true;

    console.log('[LOGIN] Login exitoso para:', usuario.nombre, '\n');

    // Headers visibles en Network
    res.set('X-Auth-Status',              'SUCCESS');
    res.set('X-Auth-User',                usuario.nombre);
    res.set('X-Cipher-App-Level',         'ECC ECDH P-256 + AES-256-CBC');
    res.set('X-Cipher-Session',           'RSA-2048-OAEP + AES-256-CBC');
    res.set('X-Double-Encryption',        'Aplicacion(ECC) + Transporte(HTTPS)');
    res.set('X-ECC-Curve',                'NIST P-256');
    res.set('X-Hash-Algorithm',           'bcrypt-rounds-12');
    res.set('X-Login-Time',               new Date().toISOString());

    res.status(200).json({
      ok: true,
      message: 'Login exitoso con Cifrado a Nivel de Aplicación (ECC)',
      redirect: '/dashboard',
      user: { id: usuario.id, name: usuario.nombre, email: usuario.email },
      encryption: {
        appLevel: {
          description: 'Datos cifrados en JS antes de salir del navegador',
          algorithm: 'ECDH P-256 + AES-256-CBC',
          keyExchange: 'Diffie-Hellman sobre curva elíptica P-256',
          protege: 'Credenciales nunca viajan en texto claro'
        },
        sessionLevel: {
          description: 'Token de sesión cifrado en servidor',
          algorithm: 'RSA-2048-OAEP + AES-256-CBC',
          tipo: 'Cifrado Híbrido'
        },
        transportLevel: {
          description: 'Capa HTTPS/TLS (externa)',
          nota: 'Datos doblemente cifrados: App + Transporte'
        }
      }
    });

  } catch (err) {
    console.error('[ERROR]', err.message);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
};

exports.logout = (req, res) => {
  console.log('[SISTEMA] Cerrando sesión para:', req.session.userName);
  req.session.destroy(() => res.redirect('/login'));
};

exports.getDashboard = async (req, res) => {
  if (!req.session.loggedIn) return res.redirect('/login');
  try {
    const [rows] = await db.query(
      'SELECT nombre, email, ecc_public_key, created_at, last_login FROM usuarios WHERE id = ?',
      [req.session.userId]
    );
    const [logs] = await db.query(
      'SELECT * FROM login_logs WHERE usuario_id = ? ORDER BY timestamp DESC LIMIT 5',
      [req.session.userId]
    );
    res.render('dashboard', { usuario: rows[0], logs });
  } catch (err) {
    console.error('[ERROR]', err);
    res.redirect('/login');
  }
};
