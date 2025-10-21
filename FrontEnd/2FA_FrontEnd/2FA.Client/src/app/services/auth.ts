import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of, catchError, map, tap, BehaviorSubject } from 'rxjs'; 
import { 
  RegisterRequest, 
  RegisterResponse, 
  LoginRequest, 
  LoginResponse,
  UserProfile, 
} from '../auth_compomnent/auth.models';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'https://localhost:7295/api/Auth';
  private tokenKey = 'jwt_token';
  private loggedInStatus = false;
  private currentUserSubject = new BehaviorSubject<UserProfile | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();


  constructor(private http: HttpClient) { 
        this.checkAuthStatus().subscribe();

  }

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
    if (this.currentUserSubject.value) {
      return of(true);
    }
    // Jeśli mamy token JWT, jest zalogowany
    if (this.getToken()) {
      return of(true);
    }
    // Jeśli nie, spróbuj pobrać profil (dla sesji z ciasteczkiem Google)
    // UWAGA: Ten endpoint musi zwrócić błąd 401, jeśli użytkownik nie jest zalogowany
    return this.http.get<UserProfile>(`${this.apiUrl}/profile`, { withCredentials: true }).pipe(
      map(user => {
        this.currentUserSubject.next(user);
        return true;
      }),
      catchError(() => {
        return of(false);
      })
    );
  }

  getProfile(userId: string): Observable<UserProfile> {
    return this.http.get<UserProfile>(`${this.apiUrl}/profile/${userId}`, {
      withCredentials: true // WAŻNE: Dołącza ciasteczko do żądania
    }).pipe(
      tap(user => {
        // Po pomyślnym pobraniu profilu, zapisz dane użytkownika
        this.currentUserSubject.next(user);
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