import express, { Router } from "express";
import swaggerUi from "swagger-ui-express";
import YAML from "yamljs";

export const swaggerRouter = Router();

const swaggerDocument = YAML.load("./swagger.yaml");
swaggerRouter.use("/", swaggerUi.serve, swaggerUi.setup(swaggerDocument));
