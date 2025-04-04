import { Request, Response, NextFunction } from "express";

export const errorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  switch (true) {
    case typeof err === "string":
      const is404 = err.toLowerCase().endsWith("not found");
      const statusCode = is404 ? 404 : 400;
      return res.status(statusCode).json({ message: err });
    case err.name === "UnauthorizedError":
      return res.status(401).json({ message: "Unauthorized" });
    default:
  }
};
