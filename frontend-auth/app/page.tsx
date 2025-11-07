"use client";

import React, { useState } from "react";
import { requestOtp } from "./lib/auth";
import { useRouter } from "next/navigation";

const Signup: React.FC = () => {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<"owner" | "employee">("owner");
  const [companyName, setCompanyName] = useState("");
  const [referralCode, setReferralCode] = useState("");
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const res = await requestOtp(email);
    if (res.message === "OTP sent successfully") {
      alert("✅ OTP sent successfully! Check your backend console.");
      router.push(
        `/otp-verification?email=${email}&role=${role}&name=${name}&companyName=${companyName}&referralCode=${referralCode}`
      );
    } else {
      alert(res.message || "Error sending OTP");
    }
  };

  return (
    <div className="min-h-screen flex justify-center items-center bg-linear-to-br from-gray-900 via-gray-950 to-black text-white">
      <form
        onSubmit={handleSubmit}
        className="bg-gray-900/80 p-8 rounded-2xl shadow-lg space-y-5 w-96 border border-gray-800"
      >
        <h2 className="text-2xl font-bold text-center">Sign Up</h2>

        <input
          type="text"
          placeholder="Full Name"
          className="w-full p-3 rounded bg-gray-800 border border-gray-700"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />

        <input
          type="email"
          placeholder="Email"
          className="w-full p-3 rounded bg-gray-800 border border-gray-700"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <select
          className="w-full p-3 rounded bg-gray-800 border border-gray-700"
          value={role}
          onChange={(e) => setRole(e.target.value as "owner" | "employee")}
        >
          <option value="owner">Owner</option>
          <option value="employee">Employee</option>
        </select>

        {role === "owner" ? (
          <input
            type="text"
            placeholder="Company Name"
            className="w-full p-3 rounded bg-gray-800 border border-gray-700"
            value={companyName}
            onChange={(e) => setCompanyName(e.target.value)}
          />
        ) : (
          <input
            type="text"
            placeholder="Referral Code"
            className="w-full p-3 rounded bg-gray-800 border border-gray-700"
            value={referralCode}
            onChange={(e) => setReferralCode(e.target.value)}
          />
        )}

        <button
          type="submit"
          className="w-full bg-indigo-600 hover:bg-indigo-700 transition p-3 rounded font-semibold"
        >
          Request OTP
        </button>
      </form>
    </div>
  );
};

export default Signup;