import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [],
  templateUrl: '../dashboard_component/dashboard_component.html',
})
export class DashboardComponent {

  constructor(private authService: AuthService, private router: Router) {}

  logout(): void {
    this.authService.logout().subscribe({
      next: () => {
        console.log('Wylogowano pomyślnie.');
        this.router.navigate(['/login']);
      },
      error: (err) => {
        console.error('Błąd podczas wylogowywania', err);
        // Nawet jeśli wystąpi błąd, wyloguj lokalnie i przekieruj
        this.authService.clearToken();
        this.router.navigate(['/login']);
      }
    });
  }
}