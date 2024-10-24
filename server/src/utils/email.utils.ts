// src/utils/email.ts

import nodemailer from 'nodemailer';

export const sendResetPasswordEmail = async (email: string, token: string) => {
  const transporter = nodemailer.createTransport({
    host: 'smtp.mailtrap.io', // Mailtrap SMTP server
    port: 2525,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const resetPasswordUrl = `http://localhost:4000/api/auth/reset-password?token=${token}`;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Password Reset',
    text: `Click the following link to reset your password: ${resetPasswordUrl}`,
  };

  await transporter.sendMail(mailOptions);
};
