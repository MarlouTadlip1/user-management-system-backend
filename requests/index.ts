import express from "express";
const router = express.Router();
import { prisma } from "../db/prisma";
import { authorize } from "../_middleware/authorize";
import { Role } from "../_helpers/role";
import { Request, Response } from "express";

interface RequestBody {
  employeeId: string;
  type: string;
  items?: any[];
  status?: string;
}

router.post("/", authorize(), async (req: Request, res: Response) => {
  try {
    const { employeeId, type, items, status } = req.body as RequestBody;
    if (!employeeId || !type || !items) {
      return res
        .status(400)
        .json({ error: { message: "Employee ID, type, and items required" } });
    }

    // Create the request
    const request = await prisma.request.create({
      data: {
        employeeId:
          typeof employeeId === "string"
            ? employeeId
            : employeeId !== undefined && employeeId !== null
            ? String(employeeId)
            : "",
        type,
        items,
        status: status || "Pending",
        createdById: (req as any).user.id,
        created: new Date(),
        updated: new Date(),
      },
    });

    // Find the employee by employeeId to get numeric ID
    const employee = await prisma.employee.findUnique({
      where: { employeeId: employeeId },
    });

    if (employee) {
      // Create workflow
      try {
        await prisma.workflow.create({
          data: {
            type: "RequestSubmission",
            details: {
              requestId: request.id,
              requestType: type,
              items: items,
              description: `Request submitted by employee ${employeeId}`,
            },
            status: "Pending",
            employeeId: employee.id, // Numeric ID
            createdById: (req as any).user.id,
            created: new Date(),
            updated: new Date(),
          },
        });
      } catch (workflowError) {
        console.error(
          "Failed to create workflow in POST /requests:",
          workflowError
        );
        // Continue to return the request even if workflow creation fails
      }
    } else {
      console.warn(
        `Employee with employeeId ${employeeId} not found for workflow creation`
      );
    }

    // Transform response to match RequestService expectations
    res.status(201).json({
      id: request.id,
      employeeId:
        request.employeeId !== null && request.employeeId !== undefined
          ? request.employeeId.toString()
          : null,
      type: request.type,
      items: request.items,
      status: request.status,
      created: request.created.toISOString(),
      updated: request.updated.toISOString(),
    });
  } catch (error) {
    console.error("Error in POST /requests:", error);
    res.status(500).json({ error: { message: "Server error" } });
  }
});

router.get(
  "/employees/:employeeId",
  authorize(),
  async (req: Request, res: Response) => {
    try {
      const employee = await prisma.employee.findUnique({
        where: { employeeId: req.params.employeeId },
      });

      if (!employee) {
        return res
          .status(404)
          .json({ error: { message: "Employee not found" } });
      }

      res.json({
        id: employee.id,
        employeeId: employee.employeeId,
      });
    } catch (error) {
      console.error("Error in GET /employees/:employeeId:", error);
      res.status(500).json({ error: { message: "Server error" } });
    }
  }
);

// Other endpoints (GET /, GET /:id, PUT /:id, DELETE /:id) remain unchanged
router.get("/", authorize(), async (req: Request, res: Response) => {
  try {
    const user = (req as any).user;
    let requests;

    if (user.role === Role.Admin) {
      requests = await prisma.request.findMany({
        include: { employee: true, createdBy: true },
      });
    } else {
      requests = await prisma.request.findMany({
        where: { createdById: user.id },
        include: { employee: true, createdBy: true },
      });
    }

    const transformedRequests = requests.map((request) => ({
      id: request.id,
      employeeId:
        request.employeeId !== null && request.employeeId !== undefined
          ? request.employeeId.toString()
          : null,
      type: request.type,
      items: request.items,
      status: request.status,
      created: request.created.toISOString(),
      updated: request.updated.toISOString(),
    }));

    res.json(transformedRequests);
  } catch (error) {
    console.error("Error in GET /requests:", error);
    res.status(500).json({ error: { message: "Server error" } });
  }
});

router.get("/:id", authorize(), async (req: Request, res: Response) => {
  try {
    const request = await prisma.request.findUnique({
      where: { id: parseInt(req.params.id) },
      include: { employee: true, createdBy: true },
    });

    if (!request) {
      return res.status(404).json({ error: { message: "Request not found" } });
    }

    res.json({
      id: request.id,
      employeeId: request.employeeId,
      type: request.type,
      items: request.items,
      status: request.status,
      created: request.created.toISOString(),
      updated: request.updated.toISOString(),
    });
  } catch (error) {
    console.error("Error in GET /requests/:id:", error);
    res.status(500).json({ error: { message: "Server error" } });
  }
});

router.put(
  "/:id",
  authorize([Role.Admin]),
  async (req: Request, res: Response) => {
    try {
      const { employeeId, type, items, status } = req.body as RequestBody;

      const updateData: any = {};
      if (employeeId !== undefined) {
        updateData.employeeId = employeeId;
      }
      if (type) updateData.type = type;
      if (items) updateData.items = items;
      if (status) updateData.status = status;
      updateData.updated = new Date();

      const request = await prisma.request.update({
        where: { id: parseInt(req.params.id) },
        data: updateData,
      });

      res.json({
        id: request.id,
        employeeId:
          request.employeeId !== null && request.employeeId !== undefined
            ? request.employeeId.toString()
            : null,
        type: request.type,
        items: request.items,
        status: request.status,
        created: request.created.toISOString(),
        updated: request.updated.toISOString(),
      });
    } catch (error) {
      console.error("Error in PUT /requests/:id:", error);
      res.status(500).json({ error: { message: "Server error" } });
    }
  }
);

router.delete(
  "/:id",
  authorize([Role.Admin]),
  async (req: Request, res: Response) => {
    try {
      await prisma.request.delete({ where: { id: parseInt(req.params.id) } });
      res.status(200).json({});
    } catch (error) {
      console.error("Error in DELETE /requests/:id:", error);
      res.status(500).json({ error: { message: "Server error" } });
    }
  }
);

export default router;
