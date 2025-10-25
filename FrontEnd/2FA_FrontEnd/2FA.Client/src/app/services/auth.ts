import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject, tap, of, map, catchError } from 'rxjs';
import { 
  RegisterRequest, 
  RegisterResponse, 
  LoginRequest, 
  LoginResponse,
  UserProfile,
  ResetPasswordRequest,
  ChangePasswordRequest, 
} from '../auth_compomnent/auth.models';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'https://localhost:7295/api/Auth';
  
  public currentUserSubject = new BehaviorSubject<UserProfile | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  constructor(private http: HttpClient) {
    this.checkAuthStatus().subscribe();
  }

  register(data: RegisterRequest): Observable<RegisterResponse> {
    return this.http.post<RegisterResponse>(`${this.apiUrl}/register`, data, { withCredentials: true });
  }

  login(data: LoginRequest): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.apiUrl}/login`, data, { withCredentials: true });
  }

  getProfile(userId: string): Observable<UserProfile> {
    return this.http.get<UserProfile>(`${this.apiUrl}/profile/${userId}`, {
      withCredentials: true 
    }).pipe(
      tap(user => {
        this.currentUserSubject.next(user);     
      })
    );
  }

 
  checkAuthStatus(): Observable<boolean> {
    return this.http.get<UserProfile>(`${this.apiUrl}/profile`, { withCredentials: true }).pipe(
      map(user => {
        this.currentUserSubject.next(user);
        return true;
      }),
      catchError(() => {
        this.currentUserSubject.next(null);
        return of(false);
      })
    );
  }

  logout(): Observable<any> {
    const obs = this.http.post(`${this.apiUrl}/logout`, {}, { withCredentials: true });
    this.currentUserSubject.next(null); 
    return obs;
  }

  isLoggedIn(): boolean {
    return !!this.currentUserSubject.value;
  }

  resetPassword(data: ResetPasswordRequest): Observable<any> {
    return this.http.post(`${this.apiUrl}/reset-password`, data, { withCredentials: true });
  }

  changePassword(data: ChangePasswordRequest): Observable<any> {
    return this.http.post(`${this.apiUrl}/change-password`, data, { withCredentials: true });
  }
}