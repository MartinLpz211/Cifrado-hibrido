const forge = require('node-forge');
const EC = require('elliptic').ec;
const ec = new EC('p256');

// ── Par de claves ECC del SERVIDOR (generado al iniciar) ──────────────────────
let serverECCKeys = null;
let serverRSAKeys = null;

function initServerKeys() {
  // RSA para cifrado híbrido de sesión
  console.log('[CRYPTO] Generando RSA-2048 del servidor...');
  const rsa = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  serverRSAKeys = {
    publicKey:  forge.pki.publicKeyToPem(rsa.publicKey),
    privateKey: forge.pki.privateKeyToPem(rsa.privateKey)
  };

  // ECC P-256 para cifrado a nivel de aplicación (E2EE)
  console.log('[CRYPTO] Generando ECC P-256 del servidor...');
  serverECCKeys = ec.genKeyPair();
  console.log('[CRYPTO] Clave pública ECC servidor:', serverECCKeys.getPublic('hex').substring(0, 40) + '...');
  console.log('[CRYPTO] Claves del servidor listas.\n');
}

// Devuelve la clave pública ECC del servidor (se enviará al frontend)
function getServerECCPublicKey() {
  return serverECCKeys.getPublic('hex');
}

function getServerRSAPublicKey() {
  return serverRSAKeys.publicKey;
}

// ── CIFRADO HÍBRIDO RSA+AES (para token de sesión) ───────────────────────────
function cifradoHibrido(mensaje, rsaPubKeyPem) {
  console.log('\n[CIFRADO HÍBRIDO] Cifrando token de sesión...');
  const claveAES = forge.random.getBytesSync(32);
  const iv = forge.random.getBytesSync(16);

  const cipher = forge.cipher.createCipher('AES-CBC', claveAES);
  cipher.start({ iv });
  cipher.update(forge.util.createBuffer(mensaje, 'utf8'));
  cipher.finish();
  const mensajeCifrado = forge.util.encode64(cipher.output.getBytes());

  const publicKey = forge.pki.publicKeyFromPem(rsaPubKeyPem);
  const claveAESCifrada = forge.util.encode64(publicKey.encrypt(claveAES, 'RSA-OAEP'));

  console.log('[CIFRADO HÍBRIDO] AES key cifrada con RSA ✓');
  console.log('[CIFRADO HÍBRIDO] Token cifrado con AES-256-CBC ✓\n');

  return { iv: forge.util.encode64(iv), mensajeCifrado, claveAESCifrada };
}

function descifradoHibrido(paquete) {
  const privateKey = forge.pki.privateKeyFromPem(serverRSAKeys.privateKey);
  const claveAES = privateKey.decrypt(forge.util.decode64(paquete.claveAESCifrada), 'RSA-OAEP');
  const iv = forge.util.decode64(paquete.iv);
  const decipher = forge.cipher.createDecipher('AES-CBC', claveAES);
  decipher.start({ iv });
  decipher.update(forge.util.createBuffer(forge.util.decode64(paquete.mensajeCifrado)));
  decipher.finish();
  return decipher.output.toString('utf8');
}

// ── ECDH: Descifrar payload cifrado por el frontend ──────────────────────────
// El frontend usa ECDH para derivar un secreto compartido y cifra con AES
function descifrarPayloadECC(payloadCifrado, clientPublicKeyHex) {
  console.log('\n[E2EE / ECC] Iniciando descifrado a nivel de aplicación...');
  console.log('[E2EE] Clave pública del cliente recibida:', clientPublicKeyHex.substring(0, 40) + '...');

  // 1. ECDH: derivar secreto compartido
  const clientKey = ec.keyFromPublic(clientPublicKeyHex, 'hex');
  const sharedSecret = serverECCKeys.derive(clientKey.getPublic());
  const sharedSecretHex = sharedSecret.toString(16).padStart(64, '0');
  const aesKey = forge.util.hexToBytes(sharedSecretHex); // 256 bits — igual que Web Crypto API

  console.log('[E2EE] Secreto compartido ECDH derivado:', sharedSecretHex.substring(0, 20) + '...');

  // 2. Descifrar con AES usando el secreto compartido
  const iv = forge.util.decode64(payloadCifrado.iv);
  const decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
  decipher.start({ iv });
  decipher.update(forge.util.createBuffer(forge.util.decode64(payloadCifrado.data)));
  decipher.finish();

  const resultado = decipher.output.toString('utf8');
  console.log('[E2EE] Payload descifrado exitosamente:', resultado);
  console.log('[E2EE] Dato sensible visible SOLO en servidor, nunca en red ✓\n');

  return JSON.parse(resultado);
}

// ── ECC: generar claves para usuario (registro) ───────────────────────────────
function generarClavesECC(password) {
  console.log('[ECC] Generando par de claves P-256 para el usuario...');
  const keyPair = ec.genKeyPair();
  const publicKeyHex = keyPair.getPublic('hex');
  const privateKeyHex = keyPair.getPrivate('hex');

  const key = forge.util.bytesToHex(forge.pkcs5.pbkdf2(password, 'salt', 10000, 16));
  const ivECC = forge.random.getBytesSync(16);
  const cipherECC = forge.cipher.createCipher('AES-CBC', forge.util.hexToBytes(key));
  cipherECC.start({ iv: ivECC });
  cipherECC.update(forge.util.createBuffer(privateKeyHex, 'utf8'));
  cipherECC.finish();

  const privKeyEncrypted = JSON.stringify({
    data: forge.util.encode64(cipherECC.output.getBytes()),
    iv: forge.util.encode64(ivECC)
  });

  console.log('[ECC] Par de claves generado ✓');
  return { publicKeyHex, privKeyEncrypted };
}

module.exports = {
  initServerKeys,
  getServerECCPublicKey,
  getServerRSAPublicKey,
  cifradoHibrido,
  descifradoHibrido,
  descifrarPayloadECC,
  generarClavesECC
};
