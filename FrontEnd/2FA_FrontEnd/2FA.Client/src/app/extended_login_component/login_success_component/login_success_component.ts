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
    const userId = this.route.snapshot.queryParamMap.get('userId');

    if (!userId) {
      this.router.navigate(['/login-failed']);
      return;
    }

    this.authService.getProfile(userId).subscribe({
      next: (userProfile) => {
        console.log('Logowanie Google pomyślne, użytkownik:', userProfile);
        this.router.navigate(['/dashboard']);
      },
      error: (err) => {
        console.error('Błąd weryfikacji sesji po logowaniu Google', err);
        this.router.navigate(['/login']);
      }
    });
  }
}