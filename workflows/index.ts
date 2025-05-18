import express from "express";
import { Request, Response } from "express";
import { prisma } from "../db/prisma";
import { authorize } from "../_middleware/authorize";
import { Role } from "../_helpers/role";
import { AuthenticatedRequest } from "../_middleware/authorize";

const router = express.Router();

interface WorkflowBody {
  employeeId: number | string;
  type: string;
  details?: any;
  status?: string;
}

function formatWorkflow(workflow: any) {
  const {
    id,
    employeeId,
    type,
    details,
    status,
    created,
    updated,
    createdById,
  } = workflow;
  const employee = workflow.employee
    ? {
        id: workflow.employee.id,
        employeeId: workflow.employee.employeeId,
        position: workflow.employee.position,
        hireDate:
          workflow.employee.hireDate instanceof Date
            ? workflow.employee.hireDate.toISOString()
            : workflow.employee.hireDate,
        isActive: workflow.employee.isActive,
        userId: workflow.employee.userId,
        departmentId: workflow.employee.departmentId,
      }
    : null;
  const createdBy = workflow.createdBy
    ? {
        id: workflow.createdBy.id,
        title: workflow.createdBy.title,
        firstName: workflow.createdBy.firstName,
        lastName: workflow.createdBy.lastName,
        email: workflow.createdBy.email,
        role: workflow.createdBy.role,
        dateCreated:
          workflow.createdBy.dateCreated instanceof Date
            ? workflow.createdBy.dateCreated.toISOString()
            : workflow.createdBy.dateCreated,
        isVerified: workflow.createdBy.isVerified,
        isActive: workflow.createdBy.isActive,
      }
    : null;
  return {
    id: id.toString(),
    employeeId,
    type,
    details,
    status,
    createdById,
    created: created instanceof Date ? created.toISOString() : created,
    updated: updated instanceof Date ? updated.toISOString() : updated,
    employee,
    createdBy,
  };
}

router.post("/", authorize(), async (req: Request, res: Response) => {
  try {
    const { employeeId, type, details, status } = req.body as WorkflowBody;
    if (!employeeId || !type) {
      return res
        .status(400)
        .json({ error: { message: "employeeId and type are required" } });
    }

    // Validate and parse employeeId
    const parsedEmployeeId =
      typeof employeeId === "string" ? parseInt(employeeId, 10) : employeeId;
    if (isNaN(parsedEmployeeId)) {
      return res
        .status(400)
        .json({ error: { message: "Invalid employeeId: must be a number" } });
    }

    // Check if employee exists
    const employee = await prisma.employee.findUnique({
      where: { id: parsedEmployeeId },
    });
    if (!employee) {
      return res.status(404).json({ error: { message: "Employee not found" } });
    }

    // Ensure details is a valid JSON object
    let workflowDetails = details;
    if (typeof details === "string") {
      try {
        workflowDetails = JSON.parse(details);
      } catch (parseError) {
        return res
          .status(400)
          .json({ error: { message: "Invalid details: must be valid JSON" } });
      }
    }

    const workflow = await prisma.workflow.create({
      data: {
        employeeId: parsedEmployeeId,
        type,
        details: workflowDetails || {},
        status: status || "Pending",
        createdById: (req as any).user.id,
        created: new Date(),
        updated: new Date(),
      },
      include: { employee: true, createdBy: true },
    });

    res.status(201).json(formatWorkflow(workflow));
  } catch (error: any) {
    console.error("Error in POST /workflows:", error.stack || error);
    res.status(500).json({
      error: { message: error.message || "Failed to create workflow" },
    });
  }
});

router.get(
  "/",
  authorize(),
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const user = req.user;
      let workflows;
      if (user?.role === Role.Admin) {
        workflows = await prisma.workflow.findMany({
          include: { employee: true, createdBy: true },
        });
      } else {
        const employee = await prisma.employee.findFirst({
          where: { userId: user?.id },
        });
        if (!employee) {
          return res
            .status(400)
            .json({ error: { message: "Employee record not found" } });
        }
        workflows = await prisma.workflow.findMany({
          where: { employeeId: employee.id },
          include: { employee: true, createdBy: true },
        });
      }
      res.json(workflows.map(formatWorkflow));
    } catch (error: any) {
      console.error("Error in GET /workflows:", error.stack || error);
      res.status(500).json({
        error: { message: error.message || "Failed to fetch workflows" },
      });
    }
  }
);

router.get(
  "/employeeId/:employeeId",
  authorize(),
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const employee = await prisma.employee.findUnique({
        where: { employeeId: req.params.employeeId },
      });
      if (!employee) {
        return res
          .status(404)
          .json({ error: { message: "Employee not found" } });
      }

      if (req.user?.role !== Role.Admin) {
        const userEmployee = await prisma.employee.findFirst({
          where: { userId: req.user?.id },
        });
        if (!userEmployee || userEmployee.id !== employee.id) {
          return res.status(401).json({ error: { message: "Unauthorized" } });
        }
      }

      const workflows = await prisma.workflow.findMany({
        where: { employeeId: employee.id },
        include: { employee: true, createdBy: true },
      });

      res.json(workflows.map(formatWorkflow));
    } catch (error: any) {
      console.error(
        "Error in GET /workflows/employeeId/:employeeId:",
        error.stack || error
      );
      res.status(500).json({
        error: { message: error.message || "Failed to fetch workflows" },
      });
    }
  }
);

router.get(
  "/:id",
  authorize(),
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const workflow = await prisma.workflow.findUnique({
        where: { id: parseInt(req.params.id) },
        include: { employee: true, createdBy: true },
      });
      if (!workflow) {
        return res
          .status(404)
          .json({ error: { message: "Workflow not found" } });
      }

      if (req.user?.role !== Role.Admin) {
        const employee = await prisma.employee.findFirst({
          where: { userId: req.user?.id },
        });
        if (!employee || workflow.employeeId !== employee.id) {
          return res.status(401).json({ error: { message: "Unauthorized" } });
        }
      }

      res.json(formatWorkflow(workflow));
    } catch (error: any) {
      console.error("Error in GET /workflows/:id:", error.stack || error);
      res.status(500).json({
        error: { message: error.message || "Failed to fetch workflow" },
      });
    }
  }
);

router.put(
  "/:id",
  authorize([Role.Admin]),
  async (req: Request, res: Response) => {
    try {
      const { status, type, details } = req.body as WorkflowBody;
      const id = parseInt(req.params.id);

      if (!status && !type && !details) {
        return res
          .status(400)
          .json({ error: { message: "At least one field is required" } });
      }

      const workflow = await prisma.workflow.findUnique({
        where: { id },
      });
      if (!workflow) {
        return res
          .status(404)
          .json({ error: { message: "Workflow not found" } });
      }

      let workflowDetails = details;
      if (typeof details === "string") {
        try {
          workflowDetails = JSON.parse(details);
        } catch (parseError) {
          return res
            .status(400)
            .json({
              error: { message: "Invalid details: must be valid JSON" },
            });
        }
      }

      const updatedWorkflow = await prisma.workflow.update({
        where: { id },
        data: {
          status,
          type,
          details: workflowDetails,
          updated: new Date(),
        },
        include: { employee: true, createdBy: true },
      });

      res.json(formatWorkflow(updatedWorkflow));
    } catch (error: any) {
      console.error("Error in PUT /workflows/:id:", error.stack || error);
      res.status(500).json({
        error: { message: error.message || "Failed to update workflow" },
      });
    }
  }
);

router.delete(
  "/:id",
  authorize([Role.Admin]),
  async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id);
      const workflow = await prisma.workflow.findUnique({
        where: { id },
      });
      if (!workflow) {
        return res
          .status(404)
          .json({ error: { message: "Workflow not found" } });
      }

      await prisma.workflow.delete({ where: { id } });
      res.json({});
    } catch (error: any) {
      console.error("Error in DELETE /workflows/:id:", error.stack || error);
      res.status(500).json({
        error: { message: error.message || "Failed to delete workflow" },
      });
    }
  }
);

export default router;
