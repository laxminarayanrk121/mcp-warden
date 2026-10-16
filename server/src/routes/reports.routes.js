import { createRouter } from "../http-shim.js";
import { getReports, getReportById, getReportMarkdown } from "../controllers/reports.controller.js";

const router = createRouter();

router.get("/", getReports);
router.get("/:id", getReportById);
router.get("/:id/md", getReportMarkdown);

export default router;
