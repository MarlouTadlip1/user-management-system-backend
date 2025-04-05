import { Request, Response, NextFunction } from "express";
import { expressjwt as jwt } from "express-jwt";
const config = require("config.json");
import { prisma } from "../db/prisma";
const { Role } = require("../helpers/role");

interface JwtPayload {
  id: number;
}

export function authorize(roles: string[] = []) {
  if (typeof roles === "string") {
    roles = [roles];
  }

  return [
    jwt({
      secret: config.secret,
      algorithms: ["HS256"],
      credentialsRequired: true,
      getToken: (req) => {
        if (
          req.headers.authorization &&
          req.headers.authorization.split(" ")[0] === "Bearer"
        ) {
          return req.headers.authorization.split(" ")[1];
        } else if (req.cookies && req.cookies.refreshToken) {
          return req.cookies.refreshToken;
        }
        return null;
      },
    }),

    // authorize based on user role
    async (req: Request, res: Response, next: NextFunction) => {
      const user = req.user as JwtPayload;

      if (!user || !user.id) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      const account = await prisma.account.findUnique({
        where: { id: user.id },
        include: { refreshTokens: true },
      });

      if (!account || (roles.length && !roles.includes(account.role))) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      req.user = {
        id: account.id,
        role: account.role,
        ownsToken: (token: string) =>
          !!account.refreshTokens.find(
            (x: { token: string | null }) =>
              x.token !== null && x.token === token
          ),
      };

      next();
    },
  ];
}
