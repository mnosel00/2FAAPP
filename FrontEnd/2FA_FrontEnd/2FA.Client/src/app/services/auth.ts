import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of, catchError, map, tap } from 'rxjs'; 
import { 
  RegisterRequest, 
  RegisterResponse, 
  LoginRequest, 
  LoginResponse, 
} from '../auth_compomnent/auth.models';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'https://localhost:7295/api/Auth';
  private tokenKey = 'jwt_token';
  private loggedInStatus = false;

  constructor(private http: HttpClient) { }

  register(data: RegisterRequest): Observable<RegisterResponse> {
    return this.http.post<RegisterResponse>(`${this.apiUrl}/register`, data);
  }

  login(data: LoginRequest): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.apiUrl}/login`, data);
  }

  logout(): Observable<any> {
    const token = this.getToken();
    this.clearToken(); 
    return this.http.post(`${this.apiUrl}/logout`, {});
  }

  checkAuthStatus(): Observable<boolean> {
    // Sprawdź najpierw token JWT (dla logowania hasłem)
    if (this.getToken()) {
      this.loggedInStatus = true;
      return of(true);
    }
    // Jeśli nie ma tokenu, zapytaj backend (dla logowania Google)
       return this.http.get('/api/users/profile').pipe(
      map(response => {
        this.loggedInStatus = true;
        return true; // Sukces, użytkownik jest zalogowany
      }),
      catchError(error => {
        this.loggedInStatus = false;
        return of(false); // Błąd (np. 401), użytkownik nie jest zalogowany
      })
    );
  }

  saveToken(token: string): void {
    localStorage.setItem(this.tokenKey, token);
    this.loggedInStatus = true;
  }

  getToken(): string | null {
    return localStorage.getItem(this.tokenKey);
  }

  clearToken(): void {
    localStorage.removeItem(this.tokenKey);
    this.loggedInStatus = false;
  }

  isLoggedIn(): boolean {
    return !!this.getToken();
  }
}