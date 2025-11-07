import express from "express";
import { verifyReferralCode } from "../controllers/referralController";

const router = express.Router();
router.post("/verify-referral", verifyReferralCode);

export default router;