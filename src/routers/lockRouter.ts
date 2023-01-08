import { Router } from "express";
import { nerdServer, NerdVersion } from "../index.js";
import sse from "../sse.js";
import { authUser } from "../utils.js";
import roomRouter from "./roomRouter.js";
import userRouter from "./userRouter.js";
import rateLimit from "express-rate-limit";

const router = Router();

router.get("/", (req, res) => {
    // send a simple Hello World message
    res.json({ message: "Hello World!" });
});

router.get("/info", (req, res) => {
    res.json({
        version: NerdVersion,
        regAllowed: nerdServer.config.allowReg
    });
});

router.get("/sse", rateLimit({
    windowMs: 60000,
    max: 5,
    standardHeaders: true
}), authUser, sse);

router.use("/users", userRouter);
router.use("/rooms", roomRouter);

export default router;