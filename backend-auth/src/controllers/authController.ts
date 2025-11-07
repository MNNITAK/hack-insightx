// src/controllers/authController.ts
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import { User } from "../models/User";
import Company from "../models/Company";
import crypto from "crypto";
import Otp from "../models/Otp";

import { sendEmail } from "../utils/sendEmail";

const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key_dev";

// Generate random 6-digit OTP
const generateOtp = (): string => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

/* ============================================================================
   1️⃣ REQUEST OTP
============================================================================ */
export const requestOtp = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    console.log("📨 Sending OTP to:", email);

    const otp = generateOtp();

    // Hash OTP before saving
    const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");

    await sendEmail({
        to: email,
        subject: "Your OTP Code",
        text: `Your OTP is: ${otp}`,
      });
    // Remove existing OTP if any
    await Otp.deleteOne({ email });

    // Save OTP in MongoDB with expiry time (5 min)
    await Otp.create({
      email,
      otp: hashedOtp,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    // TODO: Replace this with actual email/SMS send logic
    console.log(`📩 OTP for ${email}: ${otp}`);

    return res.status(200).json({ message: "OTP sent successfully" });
  } catch (error) {
    console.error("❌ Error sending OTP:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

/* ============================================================================
   2️⃣ VERIFY OTP (for both owner & employee)
============================================================================ */
export const verifyOtpCode = async (req: Request, res: Response) => {
  try {
    const { email, otp, role, name, companyName, referralCode } = req.body;
    if (!email || !otp)
      return res.status(400).json({ message: "Email and OTP required" });

    // Find OTP in DB
    const userOtp = await Otp.findOne({ email });
    if (!userOtp) return res.status(401).json({ message: "OTP not found or expired" });

    // Check expiration
    if (userOtp.expiresAt < Date.now())
      return res.status(401).json({ message: "OTP expired" });

    // Compare OTP hash
    const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");
    if (hashedOtp !== userOtp.otp)
      return res.status(401).json({ message: "Invalid OTP" });

    // ✅ OTP verified → delete OTP entry
    await Otp.deleteOne({ email });

    // Continue based on role
    let companyCode: string | null = null;

    if (role === "owner") {
      const existingOwner = await User.findOne({ email });
      if (existingOwner)
        return res.status(400).json({ message: "Owner already registered" });

      // Generate new company code
      companyCode = uuidv4().replace(/-/g, "").slice(0, 6).toUpperCase();

      // Create company record
      await Company.create({
        name: companyName,
        companyCode,
        ownerEmail: email,
      });

      // Create owner user
      await User.create({
        name,
        email,
        role: "owner",
        companyName,
        companyCode,
      });
    } else if (role === "employee") {
      // Verify referral code (companyCode)
      const company = await Company.findOne({ companyCode: referralCode });
      if (!company)
        return res.status(404).json({ message: "Invalid referral code" });

      await User.create({
        name,
        email,
        role: "employee",
        companyCode: referralCode,
        referredBy: company.ownerEmail,
      });
      companyCode = referralCode;
    } else {
      return res.status(400).json({ message: "Role must be owner or employee" });
    }

    // Generate JWT token
    const token = jwt.sign({ email, role, companyCode }, JWT_SECRET, {
      expiresIn: "2h",
    });

    return res.status(200).json({
      message: "OTP verified successfully",
      token,
      companyCode,
    });
  } catch (error) {
    console.error("❌ Verify OTP error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

/* ============================================================================
   3️⃣ OWNER SIGNUP (separate endpoint if needed)
============================================================================ */
export const ownerSignup = async (req: Request, res: Response) => {
  try {
    const { name, email, companyName, otp } = req.body;

    if (!name || !email || !companyName || !otp) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // 1️⃣ Verify OTP from DB
    const userOtp = await Otp.findOne({ email });
    if (!userOtp) {
      return res.status(401).json({ message: "OTP not found" });
    }

    if (userOtp.expiresAt < Date.now()) {
      return res.status(401).json({ message: "OTP expired" });
    }

    const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");
    if (hashedOtp !== userOtp.otp) {
      return res.status(401).json({ message: "Invalid OTP" });
    }

    await Otp.deleteOne({ email });

    // 2️⃣ Check if owner already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Owner already registered" });
    }

    // 3️⃣ Generate a unique company code
    const companyCode = uuidv4().replace(/-/g, "").slice(0, 6).toUpperCase();

    // 4️⃣ Create owner user in DB
    const newOwner = new User({
      name,
      email,
      role: "owner",
      companyName,
      companyCode,
    });

    await newOwner.save();

    // 5️⃣ Generate JWT
    const token = jwt.sign(
      { email, role: "owner", companyCode },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    return res.status(201).json({
      message: "Owner registered successfully",
      token,
      companyCode,
    });
  } catch (error) {
    console.error("❌ Owner signup error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};
