import { Account } from "@prisma/client";
import { Role } from "../helpers/role";

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        role: Role;
        ownsToken: (token: string) => boolean;
      };
    }
  }
}
