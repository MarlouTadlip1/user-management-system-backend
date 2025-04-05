import { NextFunction, Request } from "express";
import { Schema } from "joi";

export const validateRequest = (
  req: Request,
  next: NextFunction,
  schema: Schema
) => {
  const options = {
    abortEarly: false,
    allowUnknown: true,
    stripUnknown: true,
  };
  const { error, value } = schema.validate(req.body, options);
  if (error) {
    const errorMessage = error.details
      .map((detail) => detail.message)
      .join(", ");
    return next(new Error(errorMessage));
  }
  req.body = value;
  next();
};
