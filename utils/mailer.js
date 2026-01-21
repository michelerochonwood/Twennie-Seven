const nodemailer = require('nodemailer');

function createTransport() {
  // Recommended vars:
  // SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: process.env.SMTP_USER
      ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      : undefined
  });
}

async function sendMail({ to, subject, html, text }) {
  const transporter = createTransport();
  const from = process.env.SMTP_FROM || 'Twennie <info@twennie.com>';
  return transporter.sendMail({ from, to, subject, html, text });
}

module.exports = { sendMail };
