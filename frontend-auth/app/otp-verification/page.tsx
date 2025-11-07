"use client";

import React, { useState } from "react";
import { verifyOtp } from "../lib/auth";
import { useRouter, useSearchParams } from "next/navigation";

const OtpVerification: React.FC = () => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const email = searchParams.get("email") || "";
  const role = (searchParams.get("role") as "owner" | "employee") || "owner";
  const name = searchParams.get("name") || "";
  const companyName = searchParams.get("companyName") || "";
  const referralCode = searchParams.get("referralCode") || "";

  const [otp, setOtp] = useState("");
  const [loading, setLoading] = useState(false);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    const payload = {
      email,
      otp,
      role,
      name,
      companyName,
      referralCode,
    };

    const res = await verifyOtp(payload);
    setLoading(false);

    if (res.token) {
      localStorage.setItem("token", res.token);
      alert("✅ OTP Verified Successfully!");
      router.push("/dashboard");
    } else {
      alert(res.message || "Verification failed");
    }
  };

  return (
    <div className="min-h-screen flex justify-center items-center bg-linear-to-br from-gray-900 via-gray-950 to-black text-white">
      <form
        onSubmit={handleVerify}
        className="bg-gray-900/80 p-8 rounded-2xl shadow-lg space-y-5 w-80 border border-gray-800"
      >
        <h2 className="text-2xl font-bold text-center">Verify OTP</h2>

        <input
          type="text"
          placeholder="Enter 6-digit OTP"
          className="w-full p-3 rounded bg-gray-800 border border-gray-700 text-center tracking-widest"
          value={otp}
          onChange={(e) => setOtp(e.target.value)}
        />

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-green-600 hover:bg-green-700 transition p-3 rounded font-semibold disabled:opacity-50"
        >
          {loading ? "Verifying..." : "Verify OTP"}
        </button>
      </form>
    </div>
  );
};

export default OtpVerification;