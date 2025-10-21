import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject, tap, of, map, catchError } from 'rxjs';
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
  
  public currentUserSubject = new BehaviorSubject<UserProfile | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  constructor(private http: HttpClient) {
    // Przy starcie aplikacji próbujemy odzyskać sesję na podstawie ciasteczka
    this.checkAuthStatus().subscribe();
  }

  // ZMIANA: Dodano withCredentials: true
  register(data: RegisterRequest): Observable<RegisterResponse> {
    return this.http.post<RegisterResponse>(`${this.apiUrl}/register`, data, { withCredentials: true });
  }

  // ZMIANA: Dodano withCredentials: true i usunięto obsługę tokenu
  login(data: LoginRequest): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.apiUrl}/login`, data, { withCredentials: true });
  }

  // ZMIANA: Dodano withCredentials: true
  getProfile(userId: string): Observable<UserProfile> {
    return this.http.get<UserProfile>(`${this.apiUrl}/profile/${userId}`, {
      withCredentials: true 
    }).pipe(
      tap(user => {
        this.currentUserSubject.next(user);     
      })
    );
  }

  // ZMIANA: Główna metoda do weryfikacji sesji przy starcie aplikacji
  checkAuthStatus(): Observable<boolean> {
    // Endpoint /profile bez ID powinien zwracać dane zalogowanego użytkownika na podstawie ciasteczka
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

  // ZMIANA: Dodano withCredentials: true i uproszczono logikę
  logout(): Observable<any> {
    const obs = this.http.post(`${this.apiUrl}/logout`, {}, { withCredentials: true });
    this.currentUserSubject.next(null); // Natychmiast czyścimy stan użytkownika
    return obs;
  }

  // ZMIANA: Metoda opiera się już tylko na stanie w serwisie
  isLoggedIn(): boolean {
    return !!this.currentUserSubject.value;
  }
}