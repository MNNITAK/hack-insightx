import { Request, Response } from "express";
import { User } from "../models/User";
import { verifyOtp } from "../utils/otpStore";
import jwt from "jsonwebtoken";

const JWT_SECRET = "super_secret_key";

// Step 1: Employee Signup
export const employeeSignup = async (req: Request, res: Response) => {
  try {
    const { email, name, otp, companyCode } = req.body;

    if (!email || !name || !otp || !companyCode) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Step 2: Verify OTP
    const isValid = verifyOtp(email, otp);
    if (!isValid) {
      return res.status(401).json({ message: "Invalid or expired OTP" });
    }

    // Step 3: Find company by referral code
    const owner = await User.findOne({ companyCode, role: "owner" });
    if (!owner) {
      return res.status(404).json({ message: "Invalid company code" });
    }

    // Step 4: Check if employee already exists
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Step 5: Create employee user
    const employee = new User({
      email,
      name,
      role: "employee",
      companyCode,
      companyName: owner.companyName,
    });

    await employee.save();

    // Step 6: Generate JWT token
    const token = jwt.sign(
      { email, role: "employee", companyCode },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(201).json({
      message: "Employee registered successfully",
      token,
      user: {
        email: employee.email,
        name: employee.name,
        role: employee.role,
        companyName: employee.companyName,
      },
    });
  } catch (error) {
    console.error("Employee signup error:", error);
    res.status(500).json({ message: "Server error" });
  }
};