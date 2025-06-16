
const express = require('express');
const multer = require('multer');
const forge = require('node-forge');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Verificar carpeta de uploads
const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const upload = multer({ dest: 'uploads/' });

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

app.post('/verificar', upload.single('p12file'), (req, res) => {
  const password = req.body.password;
  const filePath = req.file.path;

  try {
    const p12Buffer = fs.readFileSync(filePath);
    const p12Der = forge.util.createBuffer(p12Buffer.toString('binary'));
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    const cert = certBags[forge.pki.oids.certBag][0].cert;
    const subject = cert.subject.attributes;

    const nombre = subject.find(attr => attr.name === 'commonName')?.value || '(sin nombre)';
    const correo = subject.find(attr => attr.name === 'emailAddress')?.value || '(sin correo)';
    const carrera = subject.find(attr => attr.shortName === 'OU')?.value || '(sin carrera)';

    res.send(`
      <h3>✅ Acceso concedido</h3>
      <p><strong>Nombre:</strong> ${nombre}</p>
      <p><strong>Correo:</strong> ${correo}</p>
      <p><strong>Carrera:</strong> ${carrera}</p>
      <a href="/">Volver</a>
    `);
  } catch (err) {
    console.error(err);
    res.send(`<h3 style="color:red;">❌ Error al validar el certificado</h3><p>${err.message}</p><a href="/">Volver</a>`);
  } finally {
    fs.unlinkSync(filePath);
  }
});

app.listen(PORT, () => console.log("Servidor activo en puerto " + PORT));
