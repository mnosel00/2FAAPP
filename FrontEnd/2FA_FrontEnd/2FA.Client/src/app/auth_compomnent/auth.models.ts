export interface RegisterRequest {
  email: string;
  password: string;
}

export interface RegisterResponse {
  userId: string;
  setupKey: string;
  qrCodeUri: string;
}

export interface LoginRequest {
  email: string;
  password: string;
  twoFactorCode?: string;
}

export interface LoginResponse {
  twoFactorRequired?: boolean;
  userId: string;
  token?: string;
}

export interface UserProfile {
  userId: string;
  email: string;
  name?: string; // Opcjonalne, w zależności od tego co zwraca backend
}

