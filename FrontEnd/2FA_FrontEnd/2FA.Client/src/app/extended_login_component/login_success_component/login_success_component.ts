import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../../services/auth';

@Component({
  selector: 'app-login-success',
  standalone: true,
  imports: [],
  template: '<p>Logowanie pomyślne! Trwa przekierowywanie...</p>',
})
export class LoginSuccessComponent implements OnInit {
  constructor(private route: ActivatedRoute,
    private router: Router,
    private authService: AuthService) {}

   ngOnInit(): void {
    // Krok 1: Odbierz userId z adresu URL
    const userId = this.route.snapshot.queryParamMap.get('userId');

    if (!userId) {
      // Jeśli z jakiegoś powodu brakuje userId, przekieruj na stronę błędu
      this.router.navigate(['/login-failed']);
      return;
    }

    // Krok 2: Wykonaj zapytanie o profil
    this.authService.getProfile(userId).subscribe({
      next: (userProfile) => {
        // Krok 3 (Sukces): Zapisano dane użytkownika, przekieruj na dashboard
        console.log('Logowanie Google pomyślne, użytkownik:', userProfile);
        this.router.navigate(['/dashboard']);
      },
      error: (err) => {
        // Krok 3 (Błąd): Sesja nieprawidłowa, przekieruj na stronę logowania
        console.error('Błąd weryfikacji sesji po logowaniu Google', err);
        this.router.navigate(['/login']);
      }
    });
  }
}