// src/models/Company.ts
import mongoose, { Schema, Document } from "mongoose";

export interface ICompany extends Document {
  name: string;
  companyCode: string; // referral code
  ownerEmail: string;
  createdAt: Date;
}

const companySchema = new Schema<ICompany>({
  name: { type: String, required: true },
  companyCode: { type: String, required: true, unique: true },
  ownerEmail: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model<ICompany>("Company", companySchema);