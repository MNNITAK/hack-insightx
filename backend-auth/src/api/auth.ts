export interface VerifyOtpPayload {
    email: string;
    otp: string;
    role: "owner" | "employee";
    name?: string;
    companyName?: string;
    referralCode?: string;
  }
  
  const BASE_URL = "http://localhost:4000/auth";
  
  export const requestOtp = async (email: string) => {
    const res = await fetch(`${BASE_URL}/request-otp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    return res.json();
  };
  
  export const verifyOtp = async (data: VerifyOtpPayload) => {
    const res = await fetch(`${BASE_URL}/verify-otp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return res.json();
  };  