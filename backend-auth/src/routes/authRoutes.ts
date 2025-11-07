import express from "express";
import { requestOtp, verifyOtpCode, ownerSignup } from "../controllers/authController";
import { employeeSignup } from "../controllers/employeeController";
import { verifyToken, AuthRequest } from "../middlewares/authMiddleware";
const router = express.Router();

router.post("/request-otp", requestOtp);
router.post("/verify-otp", verifyOtpCode);
router.post("/owner-signup", ownerSignup); 
router.post("/employee-signup", employeeSignup);

router.get("/me", verifyToken, (req: AuthRequest, res) => {
    res.json({ user: req.user });
  });


router.post("/owner-signup", ownerSignup);

export default router;