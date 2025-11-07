interface OtpEntry {
    email: string;
    otp: string;
    expiresAt: number;
  }
  
  const otpStore = new Map<string, OtpEntry>();
  
  // generate random 6-digit OTP
  export const generateOtp = (): string => {
    return Math.floor(100000 + Math.random() * 900000).toString();
  };
  
  // save OTP in memory
  export const saveOtp = (email: string, otp: string, ttlMinutes = 5) => {
    otpStore.set(email, {
      email,
      otp,
      expiresAt: Date.now() + ttlMinutes * 60 * 1000,
    });
  };
  
  // verify OTP
  export const verifyOtp = (email: string, otp: string): boolean => {
    const entry = otpStore.get(email);
    if (!entry) return false;
    const isValid = entry.otp === otp && Date.now() < entry.expiresAt;
    if (isValid) otpStore.delete(email); // remove after verification
    return isValid;
  };  