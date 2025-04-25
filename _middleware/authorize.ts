import { Request, Response, NextFunction } from "express";
import { expressjwt as jwt, GetVerificationKey } from "express-jwt";
const config = require("../config.json");
import { prisma } from "../db/prisma";
import { Role } from "../_helpers/role";

interface JwtPayload {
  id: number;
  role: string;
}

export interface AuthenticatedRequest extends Request {
  auth?: {
    id: number;
    role: string;
  };
  user?: {
    id: number;
    role: Role;
    ownsToken: (token: string) => boolean;
  };
}

export function authorize(roles: string[] = []) {
  if (typeof roles === "string") {
    roles = [roles];
  }

  return [
    // Authenticate with JWT
    jwt({
      secret: config.secret,
      algorithms: ["HS256"],
      requestProperty: "auth", // This tells express-jwt to store the decoded token in req.auth
    }),

    // Authorize based on user role
    async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      // Check if authentication succeeded
      if (!req.auth?.id) {
        return res
          .status(401)
          .json({ message: "Unauthorized - Invalid token" });
      }

      const account = await prisma.account.findUnique({
        where: { id: req.auth.id },
        include: { refreshTokens: true },
      });

      if (!account) {
        return res
          .status(401)
          .json({ message: "Unauthorized - Account not found" });
      }

      // Check if user has required role
      if (roles.length && !roles.includes(account.role)) {
        return res
          .status(403)
          .json({ message: "Forbidden - Insufficient permissions" });
      }

      // Attach user to request
      req.user = {
        id: account.id,
        role: account.role as Role,
        ownsToken: (token: string) =>
          !!account.refreshTokens.find(
            (rt) => rt.token === token && !rt.isExpired && rt.isActive
          ),
      };

      next();
    },
  ];
}
