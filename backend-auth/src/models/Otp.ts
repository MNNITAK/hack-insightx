// src/models/Otp.ts
import mongoose, { Schema, Document } from "mongoose";

export interface IOtp extends Document {
  email: string;
  otp: string; // should store hashed OTP
  expiresAt: number;
}

const otpSchema = new Schema<IOtp>({
  email: { type: String, required: true, unique: true },
  otp: { type: String, required: true },
  expiresAt: { type: Number, required: true },
});

const Otp = mongoose.model<IOtp>("Otp", otpSchema);
export default Otp;
