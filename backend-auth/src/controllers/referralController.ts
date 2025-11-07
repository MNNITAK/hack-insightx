import { Request, Response } from "express";
import Company from "../models/Company";

// POST /auth/verify-referral
export const verifyReferralCode = async (req: Request, res: Response) => {
  try {
    const { referralCode } = req.body;

    if (!referralCode) {
      return res.status(400).json({ message: "Referral code required" });
    }

    // Look up the company by its unique code
    const company = await Company.findOne({ companyCode: referralCode });

    if (!company) {
      return res.status(404).json({ message: "Invalid referral code" });
    }

    // If found, respond with the owner’s email (and optionally company name)
    return res.status(200).json({
      message: "Referral code valid",
      ownerEmail: company.ownerEmail,
      companyName: company.name,
    });
  } catch (error) {
    console.error("❌ Error verifying referral code:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};