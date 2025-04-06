import nodemailer from "nodemailer";
const config = require("../config.json");

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  from?: string;
}

export const sendEmail = async ({
  to,
  subject,
  html,
  from = config.emailFrom,
}: EmailOptions): Promise<void> => {
  const transporter = nodemailer.createTransport(config.smtpOptions);
  await transporter.sendMail({ from, to, subject, html });
};
