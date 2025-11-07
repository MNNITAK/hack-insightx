// src/models/User.ts
import mongoose, { Document, Schema } from "mongoose";

export interface IUser extends Document {
  name: string;
  email: string;
  role: "owner" | "employee";
  companyName?: string;     // only for owners
  companyCode?: string;     // referral code for employees/owners
  referredBy?: string;      // email of the owner (for employees)
  createdAt: Date;
}

const UserSchema: Schema<IUser> = new Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    role: { type: String, enum: ["owner", "employee"], required: true },
    companyName: { type: String },
    companyCode: { type: String },
    referredBy: { type: String },
  },
  { timestamps: true }
);

export const User = mongoose.model<IUser>("User", UserSchema);