import { createRouter } from "../http-shim.js";
import { postCompare } from "../controllers/compare.controller.js";

const router = createRouter();

router.post("/", postCompare);

export default router;
