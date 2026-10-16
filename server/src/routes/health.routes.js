import { createRouter } from "../http-shim.js";
import { getHealth } from "../controllers/health.controller.js";

const router = createRouter();

router.get("/", getHealth);

export default router;