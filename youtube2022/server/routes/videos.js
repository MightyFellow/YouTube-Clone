import express from "express";
import { addVideo, random, sub, trend } from "../controllers/video.js";
import { verifyToken } from "../verifyToken.js";

const router = express.Router();

//create a video
//private endpoints
router.post("/", verifyToken, addVideo);
router.put("/:id", verifyToken, addVideo);
router.delete("/:id", verifyToken, addVideo);

//public endpoints
router.get("/find/:id", addVideo);
router.put("/view/:id", addVideo);
router.get("/trend", trend);
router.get("/random", random);
router.get("/sub", verifyToken, sub);

export default router;
