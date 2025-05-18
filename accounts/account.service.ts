import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { prisma } from "../db/prisma";
import { sendEmail } from "../_helpers/send-email";
import { Account } from "@prisma/client";
import { Role } from "../_helpers/role";
const config = require("../config.json");

interface AuthenticateParams {
  email: string;
  password: string;
  ipAddress: string;
}

interface RegisterParams {
  title: string;
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  confirmPassword: string;
  acceptTerms?: boolean;
}

interface BasicAccountDetails {
  id: number;
  title: string;
  firstName: string;
  lastName: string;
  email: string;
  role: string;
  dateCreated: string;
  isVerified: boolean;
  isActive: boolean;
}

interface ForgotPasswordParams {
  email: string;
}

interface ResetPasswordParams {
  token: string;
  password: string;
}

interface UpdateAccountParams extends Partial<RegisterParams> {
  role?: string;
  isActive?: boolean;
}

export const accountService = {
  authenticate,
  register,
  verifyEmail,
  forgotPassword,
  validateResetToken,
  resetPassword,
  getAll,
  getById,
  create,
  update,
  delete: _delete,
  refreshToken,
  revokeToken,
};

async function authenticate({
  email,
  password,
  ipAddress,
}: AuthenticateParams) {
  const account = await prisma.account.findFirst({
    where: { email },
  });

  if (!account) {
    throw "Email doesn't exist";
  }

  if (!account.isActive) {
    throw "Account is inActive. Please contact system Administrator!";
  }

  if (!account.isVerified) {
    await sendVerificationEmail(account, config.origin);
    throw "Email is not verified";
  }

  if (!(await bcrypt.compare(password, account.passwordHash))) {
    throw "Password is incorrect";
  }

  const jwtToken = generateJwtToken(account);
  const refreshToken = await generateRefreshToken(account, ipAddress);

  return {
    ...basicDetails(account),
    jwtToken,
    refreshToken: refreshToken.token,
  };
}

async function register(params: RegisterParams, origin: string) {
  if (await prisma.account.findFirst({ where: { email: params.email } })) {
    await sendAlreadyRegisteredEmail(params.email, origin);
    return; // Prevent email enumeration
  }

  const isFirstAccount = (await prisma.account.count()) === 0;
  const role = isFirstAccount ? Role.Admin : Role.User;
  const verificationToken = randomTokenString();
  const passwordHash = await hash(params.password);

  const account = await prisma.account.create({
    data: {
      title: params.title,
      firstName: params.firstName,
      lastName: params.lastName,
      email: params.email,
      passwordHash,
      role,
      verificationToken,
      isVerified: isFirstAccount,
      isActive: true,
      acceptTerms: params.acceptTerms ?? false,
    },
  });

  if (!isFirstAccount) {
    await sendVerificationEmail(account, origin);
  } else {
    await sendEmail({
      to: account.email,
      subject: "First User Login",
      html: `
        <h4>First user login</h4>
             `,
    });
  }

  return verificationToken;
}

async function verifyEmail(token: string) {
  const account = await prisma.account.findFirst({
    where: { verificationToken: token },
  });

  if (!account) {
    throw "Verification failed";
  }

  await prisma.account.update({
    where: { id: account.id },
    data: {
      isVerified: true,
      verificationToken: null,
      verified: new Date(),
    },
  });
}

async function forgotPassword(email: string, origin: string) {
  const account = await prisma.account.findFirst({ where: { email } });

  if (!account) {
    return; // Prevent email enumeration
  }

  const resetToken = randomTokenString();
  const resetTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  await prisma.account.update({
    where: { id: account.id },
    data: { resetToken, resetTokenExpires },
  });

  await sendPasswordResetEmail(account, origin);
}

async function validateResetToken(token: string) {
  const account = await prisma.account.findFirst({
    where: {
      resetToken: token,
      resetTokenExpires: { gt: new Date() },
    },
  });

  if (!account) {
    throw "Invalid token";
  }
}

async function resetPassword(token: string, password: string) {
  const account = await prisma.account.findFirst({
    where: {
      resetToken: token,
      resetTokenExpires: { gt: new Date() },
    },
  });

  if (!account) {
    throw "Invalid token";
  }

  await prisma.account.update({
    where: { id: account.id },
    data: {
      passwordHash: await hash(password),
      resetToken: null,
      resetTokenExpires: null,
      isVerified: true,
      passwordReset: new Date(),
    },
  });
}

async function getAll() {
  const accounts = await prisma.account.findMany();
  return accounts.map((x) => basicDetails(x));
}

async function getById(id: number) {
  const account = await prisma.account.findUnique({
    where: { id },
  });
  if (!account) {
    throw "Account not found";
  }
  return basicDetails(account);
}

async function create(params: RegisterParams) {
  if (await prisma.account.findFirst({ where: { email: params.email } })) {
    throw `Email ${params.email} is already registered`;
  }

  const passwordHash = await hash(params.password);
  const account = await prisma.account.create({
    data: {
      title: params.title,
      firstName: params.firstName,
      lastName: params.lastName,
      email: params.email,
      passwordHash,
      role: Role.User,
      isVerified: true, // Admin-created accounts are verified
      isActive: true,
      acceptTerms: params.acceptTerms ?? false,
    },
  });

  return basicDetails(account);
}

async function update(id: number, params: UpdateAccountParams) {
  const account = await prisma.account.findUnique({ where: { id } });
  if (!account) {
    throw "Account not found";
  }

  if (params.email && params.email !== account.email) {
    if (await prisma.account.findFirst({ where: { email: params.email } })) {
      throw `Email ${params.email} is already registered`;
    }
  }

  const updateData: any = { ...params };
  if (params.password) {
    updateData.passwordHash = await hash(params.password);
  }
  delete updateData.password;
  delete updateData.confirmPassword;

  const updatedAccount = await prisma.account.update({
    where: { id },
    data: updateData,
  });

  return basicDetails(updatedAccount);
}

async function _delete(id: number) {
  await prisma.account.delete({ where: { id } });
}

async function refreshToken({
  token,
  ipAddress,
}: {
  token: string;
  ipAddress: string;
}) {
  const refreshToken = await prisma.refreshToken.findFirst({
    where: { token, isActive: true, isExpired: false },
    include: { account: true },
  });

  if (!refreshToken || !refreshToken.account) {
    throw "Invalid refresh token";
  }

  const account = refreshToken.account;
  const newRefreshToken = await generateRefreshToken(account, ipAddress);

  await prisma.refreshToken.update({
    where: { id: refreshToken.id },
    data: {
      revoked: new Date(),
      revokedByIp: ipAddress,
      replacedByToken: newRefreshToken.token,
      isActive: false,
    },
  });

  const jwtToken = generateJwtToken(account);
  return {
    ...basicDetails(account),
    jwtToken,
    refreshToken: newRefreshToken.token,
  };
}

async function revokeToken({
  token,
  ipAddress,
}: {
  token: string;
  ipAddress: string;
}) {
  const refreshToken = await prisma.refreshToken.findFirst({
    where: { token, isActive: true },
  });

  if (!refreshToken) {
    throw "Token not found";
  }

  await prisma.refreshToken.update({
    where: { id: refreshToken.id },
    data: {
      revoked: new Date(),
      revokedByIp: ipAddress,
      isActive: false,
    },
  });
}

function basicDetails(account: Account): BasicAccountDetails {
  return {
    id: account.id,
    title: account.title,
    firstName: account.firstName,
    lastName: account.lastName,
    email: account.email,
    role: account.role,
    dateCreated: account.created.toISOString(),
    isVerified: !!account.isVerified,
    isActive: !!account.isActive,
  };
}

function generateJwtToken(account: Account) {
  return jwt.sign({ id: account.id, role: account.role }, config.secret, {
    expiresIn: "15m",
    subject: account.id.toString(),
  });
}

async function generateRefreshToken(account: Account, ipAddress: string) {
  return prisma.refreshToken.create({
    data: {
      token: randomTokenString(),
      createdByIp: ipAddress,
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      accountId: account.id,
      isActive: true,
      isExpired: false,
    },
  });
}

function randomTokenString() {
  return crypto.randomBytes(40).toString("hex");
}

async function hash(password: string): Promise<string> {
  return await bcrypt.hash(password, 10);
}

async function sendAlreadyRegisteredEmail(email: string, origin: string) {
  const resetUrl = `${origin}/account/forgot-password`;
  await sendEmail({
    to: email,
    subject: "Email Already Registered",
    html: `
      <h4>Email Already Registered</h4>
      <p>Your email ${email} is already registered.</p>
      <p>If you don't know your password please visit the <a href="${resetUrl}">forgot password</a> page.</p>
    `,
  });
}

async function sendVerificationEmail(account: Account, origin: string) {
  const verifyUrl = `${origin}/account/verify-email?token=${account.verificationToken}`;
  await sendEmail({
    to: account.email,
    subject: "Verification Email",
    html: `
      <h4>Verification Email</h4>
      <p>Thanks for registering!</p>
      <p>Please click the below link to verify your email address:</p>
      <p><a href="${verifyUrl}">${verifyUrl}</a></p>
    `,
  });
}

async function sendPasswordResetEmail(account: Account, origin: string) {
  const resetUrl = `${origin}/account/reset-password?token=${account.resetToken}`;
  await sendEmail({
    to: account.email,
    subject: "Reset Password Email",
    html: `
      <h4>Reset Password Email</h4>
      <p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
      <p><a href="${resetUrl}">${resetUrl}</a></p>
    `,
  });
}
