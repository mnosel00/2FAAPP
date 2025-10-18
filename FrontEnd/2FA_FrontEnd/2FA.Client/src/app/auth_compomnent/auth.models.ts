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
}

export interface LoginResponse {
  is2faRequired: boolean;
  token?: string; 
  jwtToken?: string; 
}

export interface Verify2FARequest {
  email: string;
  code: string;
}

export interface Verify2FAResponse {
    jwtToken: string;
}