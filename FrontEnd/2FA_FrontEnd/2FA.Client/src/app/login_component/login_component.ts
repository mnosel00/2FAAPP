import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { AuthService } from '../services/auth';
import { LoginRequest } from '../auth_compomnent/auth.models';
import { Router, RouterLink } from '@angular/router';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterLink],
  templateUrl: './login_component.html',
})
export class LoginComponent {
  loginForm: FormGroup;
  tfaForm: FormGroup;
  isTfaRequired = false;
  errorMessage: string | null = null;

  constructor(private fb: FormBuilder, private authService: AuthService,private router: Router) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required]],
    });

    this.tfaForm = this.fb.group({
      code: ['', [Validators.required, Validators.minLength(6), Validators.maxLength(6)]],
    });
  }

  // Etap 1: Weryfikacja loginu i hasła
  onLoginSubmit(): void {
    if (this.loginForm.invalid) {
      return;
    }
    this.errorMessage = null;
    
    // Wysyłamy tylko email i hasło
    this.authService.login(this.loginForm.value).subscribe({
      next: (response) => {
        if (response.twoFactorRequired) {
          // Jeśli serwer wymaga 2FA, przechodzimy do drugiego etapu
          this.isTfaRequired = true;
        } else if (response.token) {
          // Jeśli 2FA nie jest wymagane i dostaliśmy token, logowanie jest zakończone
          this.handleSuccessfulLogin(response.token);
        }
      },
      error: (err) => {
        this.errorMessage = 'Nieprawidłowy email lub hasło.';
        console.error(err);
      }
    });
  }

  // Etap 2: Weryfikacja kodu 2FA
  onTfaSubmit(): void {
    if (this.tfaForm.invalid || this.loginForm.invalid) {
      return;
    }
    this.errorMessage = null;

    // Tworzymy nowe żądanie zawierające email, hasło ORAZ kod 2FA
    const loginRequest: LoginRequest = {
      ...this.loginForm.value,
      twoFactorCode: this.tfaForm.get('code')?.value
    };

    this.authService.login(loginRequest).subscribe({
      next: (response) => {
        if (response.token) {
          // Otrzymaliśmy token, logowanie 2FA zakończone sukcesem
          this.handleSuccessfulLogin(response.token);
        }
      },
      error: (err) => {
        this.errorMessage = 'Nieprawidłowy kod weryfikacyjny.';
        console.error(err);
      }
    });
  }

  private handleSuccessfulLogin(token: string): void {
    console.log('Zalogowano pomyślnie!');
    this.authService.saveToken(token);
    this.router.navigate(['/dashboard']);
  }
}