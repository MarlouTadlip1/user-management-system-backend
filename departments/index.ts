import express from "express";
const router = express.Router();
import { prisma } from "../db/prisma";
import { authorize } from "../_middleware/authorize";
import { Role } from "../_helpers/role";
import { Request, Response } from "express";

interface DepartmentBody {
  name: string;
  description?: string;
}

router.post(
  "/",
  authorize([Role.Admin]),
  async (req: Request, res: Response) => {
    try {
      const { name, description } = req.body as DepartmentBody;
      if (!name) {
        return res.status(400).json({ message: "Name is required" });
      }

      const existingDepartment = await prisma.department.findUnique({
        where: { name },
      });
      if (existingDepartment) {
        return res
          .status(400)
          .json({ message: "Department name already exists" });
      }

      const department = await prisma.department.create({
        data: { name, description },
      });

      res.status(201).json(department);
    } catch (error) {
      res.status(500).json({ message: "Server error", error });
    }
  }
);

router.get("/", authorize(), async (req: Request, res: Response) => {
  try {
    const departments = await prisma.department.findMany({
      include: { employees: true },
    });
    res.json(departments);
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

router.get("/:id", authorize(), async (req: Request, res: Response) => {
  try {
    const department = await prisma.department.findUnique({
      where: { id: parseInt(req.params.id) },
      include: { employees: true },
    });
    if (!department) {
      return res.status(404).json({ message: "Department not found" });
    }
    res.json(department);
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

router.put(
  "/:id",
  authorize([Role.Admin]),
  async (req: Request, res: Response) => {
    try {
      const { name, description } = req.body as DepartmentBody;
      const department = await prisma.department.update({
        where: { id: parseInt(req.params.id) },
        data: { name, description },
      });
      res.json(department);
    } catch (error) {
      res.status(500).json({ message: "Server error", error });
    }
  }
);

router.delete(
  "/:id",
  authorize([Role.Admin]),
  async (req: Request, res: Response) => {
    try {
      await prisma.department.delete({
        where: { id: parseInt(req.params.id) },
      });
      res.json({ message: "Department deleted successfully" });
    } catch (error) {
      res.status(500).json({ message: "Server error", error });
    }
  }
);

export default router;
