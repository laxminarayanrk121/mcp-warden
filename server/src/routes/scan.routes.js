import { createRouter } from "../http-shim.js";
import { postScan } from "../controllers/scan.controller.js";

const router = createRouter();

router.post("/", postScan);

export default router;