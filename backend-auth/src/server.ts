import express from "express";
import cors from "cors";
import authRoutes from "./routes/authRoutes";
import referralRoutes from "./routes/referralRoutes";

import dotenv from 'dotenv';
dotenv.config();

import mongoose from "mongoose";

const MONGO_URI = process.env.MONGODB_URL;

if (!MONGO_URI) {
  console.error("❌ MONGODB_URL is not defined in .env file");
  process.exit(1); // Stop the app if MongoDB URL is missing
}

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });


const app = express();
app.use(cors());
app.use(express.json());

app.use("/auth", authRoutes);
app.use("/auth", referralRoutes);

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "auth-referral" });
});

const PORT = 4000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));