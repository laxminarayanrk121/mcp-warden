import { createRouter } from "../http-shim.js";
import { getFixtures, getFixtureById } from "../controllers/fixtures.controller.js";

const router = createRouter();

router.get("/", getFixtures);
router.get("/:id", getFixtureById);

export default router;
