import { createRouter } from "../http-shim.js";
import { postBaselines, getBaselines, deleteBaselineById } from "../controllers/baseline.controller.js";

const router = createRouter();

router.post("/", postBaselines);
router.get("/", getBaselines);
router.delete("/:id", deleteBaselineById);

export default router;
