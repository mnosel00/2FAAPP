import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth';
import { Observable } from 'rxjs'; // ZMIANA: Poprawny import
import { UserProfile } from '../auth_compomnent/auth.models';
import { CommonModule } from '@angular/common'; // ZMIANA: Dodaj ten import

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule], // ZMIANA: Dodaj CommonModule, aby działał pipe 'async' w szablonie
  templateUrl: './dashboard_component.html', // Poprawiona ścieżka
})
export class DashboardComponent {
  currentUser$: Observable<UserProfile | null>;
  
   constructor(private authService: AuthService, private router: Router) {
    this.currentUser$ = this.authService.currentUser$;
  }

  logout(): void {
    this.authService.logout().subscribe({
      // Używamy 'complete' lub po prostu polegamy na tym, że serwis już wyczyścił stan
      complete: () => {
        console.log('Wylogowano pomyślnie, przekierowuję.');
        this.router.navigate(['/login']);
      },
      error: (err) => {
        console.error('Błąd podczas wylogowywania z serwera, ale wylogowuję lokalnie.', err);
        // Nawet jeśli serwer zwróci błąd, serwis już wyczyścił stan lokalny,
        // więc po prostu przekierowujemy użytkownika.
        this.router.navigate(['/login']);
      }
    });
  }
}