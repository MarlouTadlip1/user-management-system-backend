// account.controller.ts
import { Request, Response, NextFunction } from "express";
import { AuthenticatedRequest } from "../_middleware/authorize";
import Joi from "joi";
import express from "express";
import { accountService } from "./account.service";
import { validateRequest } from "../_middleware/validate-request";
import { Role } from "../_helpers/role";
import { authorize } from "../_middleware/authorize";
import { Router } from "express";

export const router = Router();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

// Account endpoints matching fake backend
router.post("/authenticate", authenticateSchema, authenticate);
router.post("/refresh-token", refreshToken);
router.post("/revoke-token", authorize(), revokeTokenSchema, revokeToken);
router.post("/register", registerSchema, register);
router.post("/verify-email", verifyEmailSchema, verifyEmail);
router.post("/forgot-password", forgotPasswordSchema, forgotPassword);
router.post(
  "/validate-reset-token",
  validateResetTokenSchema,
  validateResetToken
);
router.post("/reset-password", resetPasswordSchema, resetPassword);
router.get("/", authorize([Role.Admin]), getAll);
router.get("/:id", authorize(), getById);
router.post("/", authorize([Role.Admin]), createSchema, create);
router.put("/:id", authorize(), updateSchema, update);
router.delete("/:id", authorize(), _delete);

function authenticateSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function registerSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    title: Joi.string().required(),
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref("password")).required(),
    acceptTerms: Joi.boolean().optional(),
  });
  validateRequest(req, next, schema);
}

function verifyEmailSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    token: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function forgotPasswordSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    email: Joi.string().email().required(),
  });
  validateRequest(req, next, schema);
}

function resetPasswordSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    token: Joi.string().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref("password")).required(),
  });
  validateRequest(req, next, schema);
}

function validateResetTokenSchema(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const schema = Joi.object({
    token: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function createSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    title: Joi.string().required(),
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref("password")).required(),
    role: Joi.string().valid(Role.Admin, Role.User).optional(),
    isActive: Joi.boolean().optional(),
  });
  validateRequest(req, next, schema);
}

function updateSchema(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const schemaRules: any = {
    title: Joi.string().empty(""),
    firstName: Joi.string().empty(""),
    lastName: Joi.string().empty(""),
    email: Joi.string().email().empty(""),
    password: Joi.string().min(6).empty(""),
    confirmPassword: Joi.string().valid(Joi.ref("password")).empty(""),
    isActive: Joi.boolean().optional(),
  };

  if (req.user?.role === Role.Admin) {
    schemaRules.role = Joi.string().valid(Role.Admin, Role.User).empty("");
  }

  const schema = Joi.object(schemaRules).with("password", "confirmPassword");
  validateRequest(req, next, schema);
}

function revokeTokenSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    token: Joi.string().empty(""),
  });
  validateRequest(req, next, schema);
}

async function authenticate(req: Request, res: Response, next: NextFunction) {
  try {
    const { email, password } = req.body;
    const ipAddress = req.ip || "0.0.0.0";
    const account = await accountService.authenticate({
      email,
      password,
      ipAddress,
    });
    setTokenCookie(res, account.refreshToken ?? "");
    res.json(account);
  } catch (error) {
    next(error);
  }
}

async function register(req: Request, res: Response, next: NextFunction) {
  try {
    const verificationToken = await accountService.register(
      req.body,
      req.get("origin") || ""
    );
    res.status(200).json({}); // Fake backend returns empty ok()
  } catch (error) {
    next(error);
  }
}

async function verifyEmail(req: Request, res: Response, next: NextFunction) {
  try {
    await accountService.verifyEmail(req.body.token);
    res.json({ message: "Verification successful, you can now login" });
  } catch (error) {
    next(error);
  }
}

async function forgotPassword(req: Request, res: Response, next: NextFunction) {
  try {
    await accountService.forgotPassword(
      req.body.email,
      req.get("origin") || ""
    );
    res.json({}); // Fake backend returns empty ok()
  } catch (error) {
    next(error);
  }
}

async function validateResetToken(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    await accountService.validateResetToken(req.body.token);
    res.json({}); // Fake backend returns empty ok()
  } catch (error) {
    next(error);
  }
}

async function resetPassword(req: Request, res: Response, next: NextFunction) {
  try {
    await accountService.resetPassword(req.body.token, req.body.password);
    res.json({ message: "Password reset successful, you can now login" });
  } catch (error) {
    next(error);
  }
}

async function getAll(req: Request, res: Response, next: NextFunction) {
  try {
    const accounts = await accountService.getAll();
    res.json(accounts);
  } catch (error) {
    next(error);
  }
}

async function getById(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  try {
    const id = Number(req.params.id);
    if (id !== req.user?.id && req.user?.role !== Role.Admin) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const account = await accountService.getById(id);
    res.json(account);
  } catch (error) {
    next(error);
  }
}

async function create(req: Request, res: Response, next: NextFunction) {
  try {
    const account = await accountService.create(req.body);
    res.json(account);
  } catch (error) {
    next(error);
  }
}

async function update(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  try {
    const id = Number(req.params.id);
    if (id !== req.user?.id && req.user?.role !== Role.Admin) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const account = await accountService.update(id, req.body);
    res.json(account);
  } catch (error) {
    next(error);
  }
}

async function _delete(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  try {
    const id = Number(req.params.id);
    if (id !== req.user?.id && req.user?.role !== Role.Admin) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    await accountService.delete(id);
    res.json({}); // Fake backend returns empty ok()
  } catch (error) {
    next(error);
  }
}

async function refreshToken(req: Request, res: Response, next: NextFunction) {
  try {
    const token = req.cookies.refreshToken || req.body.token;
    const ipAddress = req.ip || "0.0.0.0";
    const account = await accountService.refreshToken({ token, ipAddress });
    setTokenCookie(res, account.refreshToken || "");
    res.json(account);
  } catch (error) {
    next(error);
  }
}

async function revokeToken(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  try {
    const token = req.body.token || req.cookies.refreshToken;
    const ipAddress = req.ip || "0.0.0.0";

    if (!token) {
      return res.status(400).json({ message: "Token is required" });
    }

    // Check if user owns token or is admin
    const refreshToken = await prisma.refreshToken.findFirst({
      where: { token, isActive: true },
      include: { account: true },
    });

    if (
      !refreshToken ||
      (refreshToken.accountId !== req.user?.id && req.user?.role !== Role.Admin)
    ) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    await accountService.revokeToken({ token, ipAddress });
    res.json({}); // Fake backend returns empty ok()
  } catch (error) {
    next(error);
  }
}

function setTokenCookie(res: Response, token: string) {
  const cookieOptions = {
    httpOnly: true,
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    path: "/",
  };
  res.cookie("fakeRefreshToken", token, cookieOptions); // Match fake backend cookie name
}

// Error handling middleware (add to main app)
export function errorHandler(
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) {
  const status = err.status || 500;
  const message = err.message || "Something went wrong";

  res.status(status).json({
    error: { message },
  });
}

// Example of how to use the router in your main app
import { Application } from "express";
import { prisma } from "../db/prisma";

export function registerRoutes(app: Application) {
  app.use("/accounts", router);
  // Add error handler after all routes
  app.use(errorHandler);
}
