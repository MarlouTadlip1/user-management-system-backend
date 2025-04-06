const config = require("../config.json");
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { prisma } from "../db/prisma";
import { sendEmail } from "../_helpers/send-email";
import { Account } from "@prisma/client";
import { Role } from "../_helpers/role";

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
  acceptTerms: boolean;
}

interface BasicAccountDetails {
  id: number;
  title: string;
  firstName: string;
  lastName: string;
  email: string;
  role: string;
  created: Date;
  updated?: Date | null;
  isVerified: boolean;
}

// Add these new interfaces
interface ForgotPasswordParams {
  email: string;
}

interface ResetPasswordParams {
  token: string;
  password: string;
}

interface UpdateAccountParams extends Partial<RegisterParams> {
  role?: string;
}

// Update the service exports
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
};

async function authenticate({
  email,
  password,
  ipAddress,
}: AuthenticateParams) {
  const account = await prisma.account.findFirst({
    where: { email },
  });

  if (
    !account ||
    !account.isVerified ||
    !(await bcrypt.compare(password, account.passwordHash))
  ) {
    throw "Account not verified or password is incorrect";
  }

  // Generate JWT token
  const jwtToken = generateJwtToken(account);

  // Generate and save refresh token
  const refreshToken = await generateRefreshToken(account, ipAddress);

  return {
    ...basicDetails(account),
    jwtToken,
    refreshToken: refreshToken.token, // Include the refresh token in the response
  };
}

async function register(params: RegisterParams, origin: string) {
  // Validate email uniqueness
  if (await prisma.account.findFirst({ where: { email: params.email } })) {
    await sendAlreadyRegisteredEmail(params.email, origin);
    throw "Email already registered";
  }

  // Remove confirmPassword as we don't store it
  const { confirmPassword, password, ...accountData } = params;

  const isFirstAccount = (await prisma.account.count()) === 0;
  const role = isFirstAccount ? Role.Admin : Role.User;
  const verificationToken = randomTokenString();
  const passwordHash = await hash(params.password);

  const account: Account = await prisma.account.create({
    data: {
      ...accountData,
      passwordHash,
      role,
      verificationToken,
      isVerified: false,
    },
  });

  await sendVerificationEmail(account, origin);
}

async function verifyEmail(token: string) {
  const account = await prisma.account.findFirst({
    where: { verificationToken: token },
  });

  if (!account) throw "Verification failed";

  await prisma.account.update({
    where: { id: account.id },
    data: {
      verified: new Date(Date.now()),
      verificationToken: null,
      isVerified: true,
    },
  });
}

function basicDetails(account: Account): BasicAccountDetails {
  const {
    id,
    title,
    firstName,
    lastName,
    email,
    role,
    created,
    updated,
    verified,
  } = account;
  return {
    id,
    title,
    firstName,
    lastName,
    email,
    role,
    created,
    updated,
    isVerified: !!verified,
  };
}

function generateJwtToken(account: Account) {
  return jwt.sign(
    {
      id: account.id,
      role: account.role,
    },
    config.secret,
    {
      expiresIn: "15m",
      subject: account.id.toString(),
    }
  );
}

function randomTokenString() {
  return crypto.randomBytes(40).toString("hex");
}

async function sendAlreadyRegisteredEmail(email: string, origin: string) {
  const message = `You have already registered. Please check your email for verification instructions.`;
  await sendEmail({
    to: email,
    subject: "Already Registered",
    html: `<p>${message}</p>`,
  });
}

async function sendVerificationEmail(account: Account, origin: string) {
  const message = `Please use the below token to verify your email address with the /accounts/verify-email API route.`;
  const token = account.verificationToken;
  await sendEmail({
    to: account.email,
    subject: "Verify Email",
    html: `<p>${message}</p><p>${token}</p>`,
  });
}

async function hash(password: string): Promise<string> {
  return await bcrypt.hash(password, 10);
}

//CRUD
async function getAll() {
  const accounts = await prisma.account.findMany({
    include: { refreshTokens: true },
  });
  return accounts.map((x) => basicDetails(x));
}

async function getById(id: number) {
  const account = await prisma.account.findUnique({
    where: { id },
    include: { refreshTokens: true },
  });
  if (!account) throw "Account not found";
  return basicDetails(account);
}

async function create(params: RegisterParams) {
  // validate
  if (await prisma.account.findFirst({ where: { email: params.email } })) {
    throw "Email already registered";
  }

  // hash password
  const passwordHash = await hash(params.password);

  // create account
  const account = await prisma.account.create({
    data: {
      ...params,
      passwordHash,
      role: Role.User,
      isVerified: false,
    },
  });

  return basicDetails(account);
}

async function update(id: number, params: Partial<RegisterParams>) {
  const account = await prisma.account.findUnique({ where: { id } });
  if (!account) throw "Account not found";

  // validate
  if (params.email && params.email !== account.email) {
    if (await prisma.account.findFirst({ where: { email: params.email } })) {
      throw "Email already registered";
    }
  }

  // hash password if it was entered
  if (params.password) {
    const passwordHash = await hash(params.password);
    const updatedParams = { ...params, passwordHash };
  }

  // update account
  await prisma.account.update({
    where: { id },
    data: params,
  });
}

async function _delete(id: number) {
  await prisma.account.delete({ where: { id } });
}

// Add these new service methods
async function forgotPassword(email: string, origin: string) {
  const account = await prisma.account.findFirst({ where: { email } });

  if (!account) return; // Don't reveal if account doesn't exist

  // Create reset token that expires in 1 hour
  const resetToken = randomTokenString();
  const resetTokenExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

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

  if (!account) throw "Invalid or expired token";
  return account;
}

async function resetPassword(token: string, password: string) {
  const account = await validateResetToken(token);

  // Update password and clear reset token
  await prisma.account.update({
    where: { id: account.id },
    data: {
      passwordHash: await hash(password),
      resetToken: null,
      resetTokenExpires: null,
      passwordReset: new Date(),
    },
  });
}

// Add this email helper
async function sendPasswordResetEmail(account: Account, origin: string) {
  const message = `Please use the following token to reset your password:`;
  const resetLink = `${origin}/reset-password?token=${account.resetToken}`;

  await sendEmail({
    to: account.email,
    subject: "Reset Password",
    html: `
      <p>${message}</p>
      <p><a href="${resetLink}">Reset Password</a></p>
      <p>Token: ${account.resetToken}</p>
      <p>The token is valid for 1 hour.</p>
    `,
  });
}

function generateRefreshToken(account: Account, ipAddress: string) {
  return prisma.refreshToken.create({
    data: {
      token: randomTokenString(),
      createdByIp: ipAddress,
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      accountId: account.id,
      isActive: true,
      isExpired: false,
    },
  });
}
