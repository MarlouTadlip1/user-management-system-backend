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

export const accountService = {
  authenticate,
  register,
  verifyEmail,
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
    throw "Email or password is incorrect";
  }

  const jwtToken = generateJwtToken(account);

  return {
    ...basicDetails(account),
    jwtToken,
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
  return jwt.sign({ sub: account.id, id: account.id }, config.secret, {
    expiresIn: "15m",
  });
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
  const message = `Please use the below token to verify your email address with the /accounts/verify-meail api route.`;
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
