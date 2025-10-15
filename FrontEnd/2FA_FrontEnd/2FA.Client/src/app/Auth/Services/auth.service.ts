import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly apiUrl = 'https://localhost:7295/api/Auth'; // Zmień port, jeśli Twój API działa na innym

  constructor(private http: HttpClient) {}

  private getAuthHeaders(): HttpHeaders {
    const token = localStorage.getItem('auth_token');
    return new HttpHeaders().set('Authorization', token ? `Bearer ${token}` : '');
  }

  register(email: string, password: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/register`, { email, password });
  }

  login(email: string, password: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/login`, { email, password });
  }

  verify2FA(userId: string, code: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/verify2fa`, { userId, code });
  }

  getProfile(userId: string): Observable<any> {
    // W prawdziwej aplikacji użylibyśmy nagłówka Bearer, ale dla symulacji wystarczy userId
    return this.http.get(`${this.apiUrl}/profile/${userId}`);
  }

  // Pomocnicze funkcje stanu
  setToken(token: string, userId: string): void {
    localStorage.setItem('auth_token', token);
    localStorage.setItem('user_id', userId); // Uproszczone zapisanie ID
  }

  getUserId(): string | null {
    return localStorage.getItem('user_id');
  }

  isLoggedIn(): boolean {
    return !!localStorage.getItem('auth_token');
  }

  logout(): void {
    localStorage.clear();
  }
}
