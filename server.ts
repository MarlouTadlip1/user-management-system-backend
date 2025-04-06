import express, { Request, Response } from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import { errorHandler } from "./_middleware/error-handler";
import { router } from "./accounts/accounts.controller";
import { swaggerRouter } from "./_helpers/swagger";
const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: (origin, callback) => {
      callback(null, true);
    },
    credentials: true,
  })
);

app.get("/", (req: Request, res: Response) => {
  res.send("Hello World! This is the server for the accounts API.");
});
app.use("/accounts", router);
app.use("/api-docs", swaggerRouter);
app.use(errorHandler);

const port =
  process.env.NODE_ENV === "production" ? process.env.PORT || 80 : 4000;
app.listen(port, () => console.log(`Server listening on port ${port}`));
