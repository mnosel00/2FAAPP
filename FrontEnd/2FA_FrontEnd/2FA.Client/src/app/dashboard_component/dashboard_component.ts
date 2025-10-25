import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth';
import { Observable } from 'rxjs'; 
import { UserProfile } from '../auth_compomnent/auth.models';
import { CommonModule } from '@angular/common'; 
import { AbstractControl, FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';

function passwordMatcher(control: AbstractControl): { [key: string]: boolean } | null {
  const newPassword = control.get('newPassword');
  const confirmNewPassword = control.get('confirmNewPassword');
  if (newPassword?.pristine || confirmNewPassword?.pristine) {
    return null;
  }
  return newPassword && confirmNewPassword && newPassword.value !== confirmNewPassword.value ? { 'passwordsMismatch': true } : null;
}

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule], 
  templateUrl: './dashboard_component.html', 
})
export class DashboardComponent {
  currentUser$: Observable<UserProfile | null>;
  changePasswordForm: FormGroup;
  successMessage: string | null = null;
  errorMessage: string | null = null;
  
   constructor(
    private authService: AuthService, 
    private router: Router,
    private fb: FormBuilder // ZMIANA: Wstrzyknij FormBuilder
  ) {
    this.currentUser$ = this.authService.currentUser$;

    // ZMIANA: Inicjalizacja formularza zmiany hasła
    this.changePasswordForm = this.fb.group({
      oldPassword: ['', Validators.required],
      newPassword: ['', [
        Validators.required,
        Validators.minLength(8),
        Validators.pattern('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^a-zA-Z\\d]).{8,}$')
      ]],
      confirmNewPassword: ['', Validators.required]
    }, { validators: passwordMatcher });
  }

  onChangePasswordSubmit(): void {
    this.successMessage = null;
    this.errorMessage = null;

    if (this.changePasswordForm.invalid) {
      return;
    }

    this.authService.changePassword(this.changePasswordForm.value).subscribe({
      next: (response) => {
        this.successMessage = response.message || 'Hasło zostało pomyślnie zmienione.';
        this.changePasswordForm.reset(); 
      },
      error: (err: any) => {
        if (err.status === 401) {
          this.router.navigate(['/login']);
        } else if (err.error && err.error.errors) {
          this.errorMessage = err.error.errors.join(' ');
        } else {
          this.errorMessage = 'Wystąpił nieoczekiwany błąd.';
        }
      }
    });
  }

  logout(): void {
    this.authService.logout().subscribe({
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