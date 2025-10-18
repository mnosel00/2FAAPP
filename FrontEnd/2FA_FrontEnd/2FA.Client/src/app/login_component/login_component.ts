import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { AuthService } from '../services/auth';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './login_component.html',
})
export class LoginComponent {
  loginForm: FormGroup;
  tfaForm: FormGroup;
  isTfaRequired = false;
  errorMessage: string | null = null;

  constructor(private fb: FormBuilder, private authService: AuthService) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required]],
    });

    this.tfaForm = this.fb.group({
      code: ['', [Validators.required, Validators.minLength(6), Validators.maxLength(6)]],
    });
  }

  onLoginSubmit(): void {
    if (this.loginForm.invalid) {
      return;
    }
    this.errorMessage = null;
    this.authService.login(this.loginForm.value).subscribe({
      next: (response) => {
        if (response.is2faRequired) {
          this.isTfaRequired = true;
        } else {
          // Logowanie pomyślne bez 2FA
          console.log('Zalogowano pomyślnie!', response.jwtToken);
          // Tutaj zapisz token JWT (np. w localStorage) i przekieruj użytkownika
        }
      },
      error: (err) => {
        this.errorMessage = 'Nieprawidłowy email lub hasło.';
        console.error(err);
      }
    });
  }

  onTfaSubmit(): void {
    if (this.tfaForm.invalid) {
      return;
    }
    this.errorMessage = null;
    const request = {
      email: this.loginForm.get('email')?.value,
      code: this.tfaForm.get('code')?.value
    };

    this.authService.verify2fa(request).subscribe({
      next: (response) => {
        console.log('Logowanie 2FA pomyślne!', response.jwtToken);
        // Tutaj zapisz token JWT (np. w localStorage) i przekieruj użytkownika
      },
      error: (err) => {
        this.errorMessage = 'Nieprawidłowy kod weryfikacyjny.';
        console.error(err);
      }
    });
  }
}