const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  const sender_name = process.env.MAILER_DOMAIN;
  const sender_email = process.env.MAILER_EMAIL;
  const sender_password = process.env.MAILER_PASSWORD;
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: sender_email,
      pass: sender_password,
    },
  });

  const message = {
    from: `${sender_name} <${sender_email}>`,
    to: options.email,
    subject: options.subject,
    text: options.message,
  };

  const info = await transporter.sendMail(message);

  console.log('Message sent: %s', info.messageId);
};

module.exports = sendEmail;
