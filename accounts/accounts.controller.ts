import { Request, Response, NextFunction } from "express";
import Joi from "joi";
import express from "express";
import { accountService } from "./account.service";
import { validateRequest } from "../_middleware/validate-request";
import { prisma } from "../db/prisma";

import { Router } from "express";

export const router = Router();

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

router.post("/authenticate", authenticateSchema, authenticate);
router.post("/register", registerSchema, register);
router.post("/verify-email", verifyEmailSchema, verifyEmail);

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
  console.log("Registration attempt:", req.body.email);

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
