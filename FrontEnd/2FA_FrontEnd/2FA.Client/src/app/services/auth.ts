import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { 
  RegisterRequest, 
  RegisterResponse, 
  LoginRequest, 
  LoginResponse, 
  Verify2FARequest,
  Verify2FAResponse
} from '../auth_compomnent/auth.models';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'https://localhost:7295/api/Auth';

  constructor(private http: HttpClient) { }

  register(data: RegisterRequest): Observable<RegisterResponse> {
    return this.http.post<RegisterResponse>(`${this.apiUrl}/register`, data);
  }

  login(data: LoginRequest): Observable<LoginResponse> {
    // Zakładam, że endpoint do logowania to /api/Auth/login
    return this.http.post<LoginResponse>(`${this.apiUrl}/login`, data);
  }

  verify2fa(data: Verify2FARequest): Observable<Verify2FAResponse> {
    // Zakładam, że endpoint do weryfikacji kodu 2FA to /api/Auth/verify-2fa
    return this.http.post<Verify2FAResponse>(`${this.apiUrl}/verify-2fa`, data);
  }
}