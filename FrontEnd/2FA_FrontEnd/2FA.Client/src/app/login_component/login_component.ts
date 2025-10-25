import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '../services/auth';
import { LoginRequest, LoginResponse } from '../auth_compomnent/auth.models';

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

  constructor(private fb: FormBuilder, private authService: AuthService, private router: Router) {
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
        if (response.twoFactorRequired) {
          this.isTfaRequired = true;
        } else if (response.userId) {
          this.handleSuccessfulLogin(response.userId);
        }
      },
      error: (err) => {
        this.errorMessage = 'Nieprawidłowy email lub hasło.';
        console.error(err);
      }
    });
  }

  onTfaSubmit(): void {
    if (this.tfaForm.invalid || this.loginForm.invalid) {
      return;
    }
    this.errorMessage = null;

    const loginRequest: LoginRequest = {
      ...this.loginForm.value,
      twoFactorCode: this.tfaForm.get('code')?.value
    };

    this.authService.login(loginRequest).subscribe({
      next: (response) => {
        if (response.userId) {
          this.handleSuccessfulLogin(response.userId);
        } else {
          this.errorMessage = 'Logowanie nie powiodło się. Spróbuj ponownie.';
        }
      },
      error: (err) => {
        this.errorMessage = 'Nieprawidłowy kod weryfikacyjny.';
        console.error(err);
      }
    });
  }

  private handleSuccessfulLogin(userId: string): void {
    this.authService.getProfile(userId).subscribe({
      next: () => {
        console.log('Logowanie pomyślne, pobrano profil. Przekierowuję na dashboard.');
        this.router.navigate(['/dashboard']);
      },
      error: (err) => {
        console.error('Logowanie pomyślne, ale nie udało się pobrać profilu', err);
        this.errorMessage = 'Wystąpił błąd po zalogowaniu. Spróbuj ponownie.';
      }
    });
  }
}