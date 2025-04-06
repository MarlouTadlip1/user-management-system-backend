import { Request, Response, NextFunction } from "express";
import { AuthenticatedRequest } from "../_middleware/authorize"; // Adjust the path if necessary
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

router.post("/authenticate", authenticateSchema, authenticate);
router.post("/register", registerSchema, register);
router.post("/verify-email", verifyEmailSchema, verifyEmail);
router.post("/forgot-password", forgotPasswordSchema, forgotPassword);
router.post("/reset-password", resetPasswordSchema, resetPassword);
router.get("/", authorize([Role.Admin]), getAll);
router.get("/:id", authorize(), getById);
router.post("/", authorize([Role.Admin]), createSchema, create);
router.put("/:id", authorize(), updateSchema, update);
router.delete("/:id", authorize(), _delete);

function authenticateSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    email: Joi.string().required(),
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
    acceptTerms: Joi.boolean().valid(true).required(),
  });
  validateRequest(req, next, schema);
}

function verifyEmailSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    token: Joi.string().required(),
  });
  validateRequest(req, next, schema);
}

function authenticate(req: Request, res: Response, next: NextFunction) {
  const { email, password } = req.body;
  const ipAddress = req.ip || "0.0.0.0";
  accountService
    .authenticate({ email, password, ipAddress })
    .then((account) => res.json(account))
    .catch(next);
}

function register(req: Request, res: Response, next: NextFunction) {
  accountService
    .register(req.body, req.get("origin") || "")
    .then(() => {
      console.log("Registration successful for:", req.body.email);
      res.status(201).json({
        success: true,
        message:
          "Registration successful. Please check your email for verification.",
      });
    })
    .catch((error) => {
      console.error("Registration error:", error);
      if (error === "Email already registered") {
        return res.status(400).json({
          success: false,
          message: error,
        });
      }
      res.status(500).json({
        success: false,
        message: "Registration failed. Please try again later.",
      });
    });
}

function verifyEmail(req: Request, res: Response, next: NextFunction) {
  accountService
    .verifyEmail(req.body.token)
    .then(() =>
      res.json({ message: "Verification successful, you can now login" })
    )
    .catch(next);
}

function getAll(req: Request, res: Response, next: NextFunction) {
  accountService
    .getAll()
    .then((accounts) => res.json(accounts))
    .catch(next);
}

function getById(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  // Users can get their own account and admins can get any account
  if (Number(req.params.id) !== req.user?.id && req.user?.role !== Role.Admin) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  accountService
    .getById(Number(req.params.id))
    .then((account) => (account ? res.json(account) : res.sendStatus(404)))
    .catch(next);
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
  });
  validateRequest(req, next, schema);
}

function create(req: Request, res: Response, next: NextFunction) {
  accountService
    .create(req.body)
    .then((account) => res.json(account))
    .catch(next);
}

function update(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  // Users can update their own account and admins can update any account
  if (Number(req.params.id) !== req.user?.id && req.user?.role !== Role.Admin) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  accountService
    .update(Number(req.params.id), req.body as any)
    .then((account) => res.json(account))
    .catch(next);
}

function _delete(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  // Users can delete their own account and admins can delete any account
  if (Number(req.params.id) !== req.user?.id && req.user?.role !== Role.Admin) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  accountService
    .delete(Number(req.params.id))
    .then(() => res.json({ message: "Account deleted successfully" }))
    .catch(next);
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

function updateSchema(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const schemaRules: {
    title: Joi.StringSchema;
    firstName: Joi.StringSchema;
    lastName: Joi.StringSchema;
    email: Joi.StringSchema;
    password: Joi.StringSchema;
    confirmPassword: Joi.StringSchema;
    role?: Joi.StringSchema;
  } = {
    title: Joi.string().empty(""),
    firstName: Joi.string().empty(""),
    lastName: Joi.string().empty(""),
    email: Joi.string().email().empty(""),
    password: Joi.string().min(6).empty(""),
    confirmPassword: Joi.string().valid(Joi.ref("password")).empty(""),
  };

  // Only admins can update role
  if (req.user?.role === Role.Admin) {
    schemaRules.role = Joi.string().valid(Role.Admin, Role.User).empty("");
  }

  const schema = Joi.object(schemaRules).with("password", "confirmPassword");
  validateRequest(req, next, schema);
}
function forgotPassword(req: Request, res: Response, next: NextFunction) {
  accountService
    .forgotPassword(req.body.email, req.get("origin") || "")
    .then(() =>
      res.json({
        message: "Password reset instructions sent to email if account exists",
      })
    )
    .catch(next);
}

function resetPassword(req: Request, res: Response, next: NextFunction) {
  accountService
    .resetPassword(req.body.token, req.body.password)
    .then(() =>
      res.json({
        message: "Password reset successful, you can now login",
      })
    )
    .catch(next);
}
