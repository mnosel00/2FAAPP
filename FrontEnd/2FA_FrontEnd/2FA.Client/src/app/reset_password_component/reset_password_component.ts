import { Component } from '@angular/core';
import { AbstractControl, FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../services/auth';
import { ResetPasswordRequest } from '../auth_compomnent/auth.models';

// Funkcja walidująca zgodność haseł (można ją wynieść do osobnego pliku)
function passwordMatcher(control: AbstractControl): { [key: string]: boolean } | null {
  const newPassword = control.get('newPassword');
  const confirmNewPassword = control.get('confirmNewPassword');
  if (newPassword?.pristine || confirmNewPassword?.pristine) {
    return null;
  }
  return newPassword && confirmNewPassword && newPassword.value !== confirmNewPassword.value ? { 'passwordsMismatch': true } : null;
}

@Component({
  selector: 'app-reset-password',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl: './reset_password_component.html',
})
export class ResetPasswordComponent {
  resetForm: FormGroup;
  errorMessage: string | null = null;
  successMessage: string | null = null;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {
    this.resetForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      newPassword: ['', [
        Validators.required,
        Validators.minLength(8),
        Validators.pattern('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^a-zA-Z\\d]).{8,}$')
      ]],
      confirmNewPassword: ['', Validators.required],
      token: ['', [Validators.required, Validators.minLength(6), Validators.maxLength(6)]]
    }, { validators: passwordMatcher });
  }

  onSubmit(): void {
    this.errorMessage = null;
    this.successMessage = null;

    if (this.resetForm.invalid) {
      return;
    }

    const requestData: ResetPasswordRequest = this.resetForm.value;

    this.authService.resetPassword(requestData).subscribe({
      next: () => {
        this.successMessage = 'Hasło zostało pomyślnie zresetowane. Za chwilę zostaniesz przekierowany do strony logowania...';
        setTimeout(() => {
          this.router.navigate(['/login']);
        }, 3000); // Przekierowanie po 3 sekundach
      },
      error: (err:any) => {
        if (err.error && err.error.errors) {
          this.errorMessage = err.error.errors.join(' ');
        } else {
          this.errorMessage = 'Wystąpił nieoczekiwany błąd. Spróbuj ponownie.';
        }
        console.error(err);
      }
    });
  }
}