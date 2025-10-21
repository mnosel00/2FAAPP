import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth';
import { Observable } from 'rxjs/internal/Observable';
import { UserProfile } from '../auth_compomnent/auth.models';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [],
  templateUrl: '../dashboard_component/dashboard_component.html',
})
export class DashboardComponent {
  currentUser$: Observable<UserProfile | null>;
  
   constructor(private authService: AuthService, private router: Router) {
    this.currentUser$ = this.authService.currentUser$;
  }

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