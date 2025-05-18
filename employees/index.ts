// employee.router.ts
import express from "express";
import { Request, Response, NextFunction } from "express";
import { prisma } from "../db/prisma";
import { authorize } from "../_middleware/authorize";
import { Role } from "../_helpers/role";
import { AuthenticatedRequest } from "../_middleware/authorize";

const router = express.Router();

interface EmployeeBody {
  employeeId: string;
  userId?: number | string; // Match fake backend's naming
  position: string;
  hireDate: string;
  departmentId?: number | string;
  isActive?: boolean;
}

// Helper function to format employee responses like fake backend's basicDetails
function basicDetails(employee: any) {
  const { id, employeeId, position, hireDate, isActive, userId, departmentId } =
    employee;
  const account = employee.account
    ? {
        id: employee.account.id,
        title: employee.account.title,
        firstName: employee.account.firstName,
        lastName: employee.account.lastName,
        email: employee.account.email,
        role: employee.account.role,
        dateCreated: employee.account.dateCreated,
        isVerified: employee.account.isVerified,
        isActive: employee.account.isActive,
      }
    : null;
  const department = employee.department
    ? {
        id: employee.department.id,
        name: employee.department.name,
        description: employee.department.description,
      }
    : null;
  return {
    id: id, // Match fake backend's string ID
    employeeId,
    position,
    userId: userId, // Map accountId to userId
    departmentId:
      typeof departmentId === "string" ? parseInt(departmentId) : departmentId,
    hireDate: hireDate,
    isActive,
    account,
    department,
  };
}

// POST /employees
router.post(
  "/",
  authorize([Role.Admin]),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { employeeId, userId, position, hireDate, departmentId } =
        req.body as EmployeeBody;

      // Validate required fields
      if (!employeeId || !position || !hireDate) {
        return res.status(400).json({
          error: {
            message: "employeeId, position, and hireDate are required",
          },
        });
      }

      // Check if employeeId exists
      const existingEmployee = await prisma.employee.findUnique({
        where: { employeeId },
      });
      if (existingEmployee) {
        return res
          .status(400)
          .json({ error: { message: "Employee ID already exists" } });
      }

      // Validate and parse userId
      let parsedUserId: number | undefined;
      if (userId !== undefined) {
        parsedUserId = typeof userId === "string" ? parseInt(userId) : userId;
        if (isNaN(parsedUserId)) {
          return res.status(400).json({ error: { message: "Invalid userId" } });
        }
        const account = await prisma.account.findUnique({
          where: { id: parsedUserId },
        });
        if (!account) {
          return res.status(400).json({ error: { message: "User not found" } });
        }
        const existingEmployeeForUser = await prisma.employee.findFirst({
          where: { userId: parsedUserId },
        });
        if (existingEmployeeForUser) {
          return res.status(400).json({
            error: { message: "User already has an employee record" },
          });
        }
      }

      // Validate and parse departmentId
      let parsedDepartmentId: number | undefined;
      if (departmentId !== undefined) {
        parsedDepartmentId =
          typeof departmentId === "string"
            ? parseInt(departmentId)
            : departmentId;
        if (isNaN(parsedDepartmentId)) {
          return res
            .status(400)
            .json({ error: { message: "Invalid departmentId" } });
        }
        const department = await prisma.department.findUnique({
          where: { id: parsedDepartmentId },
        });
        if (!department) {
          return res
            .status(400)
            .json({ error: { message: "Department not found" } });
        }
      }

      // Validate hireDate
      const parsedHireDate = new Date(hireDate);
      if (isNaN(parsedHireDate.getTime())) {
        return res.status(400).json({ error: { message: "Invalid hireDate" } });
      }

      const employee = await prisma.employee.create({
        data: {
          employeeId,
          userId: parsedUserId,
          position,
          hireDate: parsedHireDate,
          departmentId: parsedDepartmentId,
          isActive: true,
          status: "Active", // Align with schema
        },
        include: { account: true, department: true },
      });

      res.status(200).json(basicDetails(employee));
    } catch (error: any) {
      console.error("Error in POST /employees:", error);
      res
        .status(500)
        .json({ error: { message: error.message || "Server error" } });
    }
  }
);

// GET /employees
router.get(
  "/",
  authorize(),
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const employees = await prisma.employee.findMany({
        include: { account: true, department: true },
      });
      res.json(employees.map(basicDetails));
    } catch (error) {
      res.status(500).json({ error: { message: "Server error" } });
    }
  }
);

// GET /employees/:id
router.get(
  "/:id",
  authorize(),
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const employee = await prisma.employee.findUnique({
        where: { id: parseInt(req.params.id) },
        include: { account: true, department: true },
      });
      if (!employee) {
        return res
          .status(400)
          .json({ error: { message: "Employee not found" } });
      }

      // Allow users to access their own employee record
      if (employee.userId !== req.user?.id && req.user?.role !== Role.Admin) {
        return res.status(401).json({ error: { message: "Unauthorized" } });
      }

      res.json(basicDetails(employee));
    } catch (error) {
      res.status(500).json({ error: { message: "Server error" } });
    }
  }
);

// PUT /employees/:id
router.put(
  "/:id",
  authorize([Role.Admin]),
  async (req: Request, res: Response) => {
    try {
      const { employeeId, userId, position, hireDate, departmentId, isActive } =
        req.body as EmployeeBody;
      const id = parseInt(req.params.id);

      // Check if employee exists
      const existingEmployee = await prisma.employee.findUnique({
        where: { id },
      });
      if (!existingEmployee) {
        return res
          .status(400)
          .json({ error: { message: "Employee not found" } });
      }

      // Validate userId
      if (userId && userId !== existingEmployee.userId) {
        const account = await prisma.account.findUnique({
          where: { id: typeof userId === "string" ? parseInt(userId) : userId },
        });
        if (!account) {
          return res.status(400).json({ error: { message: "User not found" } });
        }

        // Check if user already has another employee record
        const existingEmployeeForUser = await prisma.employee.findFirst({
          where: {
            userId: typeof userId === "string" ? parseInt(userId) : userId,
            id: { not: id },
          },
        });
        if (existingEmployeeForUser) {
          return res.status(400).json({
            error: { message: "User already has an employee record" },
          });
        }
      }

      // Validate departmentId
      if (departmentId && departmentId !== existingEmployee.departmentId) {
        const parsedDepartmentId =
          typeof departmentId === "string"
            ? parseInt(departmentId)
            : departmentId;
        const department = await prisma.department.findUnique({
          where: { id: parsedDepartmentId },
        });
        if (!department) {
          return res
            .status(400)
            .json({ error: { message: "Department not found" } });
        }
      }

      const employee = await prisma.employee.update({
        where: { id },
        data: {
          employeeId: employeeId || existingEmployee.employeeId,
          userId: typeof userId === "string" ? parseInt(userId) : userId,
          position: position || existingEmployee.position,
          hireDate: hireDate ? new Date(hireDate) : existingEmployee.hireDate,
          departmentId:
            typeof departmentId === "string"
              ? parseInt(departmentId)
              : departmentId,
          isActive:
            isActive !== undefined ? isActive : existingEmployee.isActive,
        },
        include: { account: true, department: true },
      });

      res.json(basicDetails(employee));
    } catch (error) {
      res.status(500).json({ error: { message: "Server error" } });
    }
  }
);

// DELETE /employees/:id
router.delete(
  "/:id",
  authorize([Role.Admin]),
  async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id);
      const employee = await prisma.employee.findUnique({
        where: { id },
      });
      if (!employee) {
        return res
          .status(400)
          .json({ error: { message: "Employee not found" } });
      }

      await prisma.employee.delete({ where: { id } });
      res.json({}); // Match fake backend's empty ok()
    } catch (error) {
      res.status(500).json({ error: { message: "Server error" } });
    }
  }
);

// PATCH /employees/:id (replaces POST /employees/transfer)
router.patch(
  "/:id",
  authorize([Role.Admin]),
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const id = parseInt(req.params.id);
      const { departmentId } = req.body;

      if (!departmentId) {
        return res
          .status(400)
          .json({ error: { message: "Department ID required" } });
      }

      // Find the employee
      const employee = await prisma.employee.findUnique({
        where: { id },
      });
      if (!employee) {
        return res
          .status(400)
          .json({ error: { message: "Employee not found" } });
      }

      // Validate department
      const department = await prisma.department.findUnique({
        where: { id: departmentId },
      });
      if (!department) {
        return res
          .status(400)
          .json({ error: { message: "Invalid department ID" } });
      }

      // Update departmentId
      const updatedEmployee = await prisma.employee.update({
        where: { id },
        data: { departmentId },
        include: { account: true, department: true },
      });

      res.json(basicDetails(updatedEmployee));
    } catch (error) {
      res.status(500).json({ error: { message: "Server error" } });
    }
  }
);

router.get("/hello", (req: Request, res: Response) => {
  res.send("Hello from employees API!");
});

export default router;
