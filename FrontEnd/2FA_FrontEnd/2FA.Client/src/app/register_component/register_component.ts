import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule,AbstractControl } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { QRCodeComponent } from 'angularx-qrcode'; 
import { RouterLink } from '@angular/router'; 
import { AuthService } from '../services/auth';
import { RegisterResponse } from '../auth_compomnent/auth.models';

function passwordMatcher(control: AbstractControl): { [key: string]: boolean } | null {
  const password = control.get('password');
  const confirmPassword = control.get('confirmPassword');
  if (password?.pristine || confirmPassword?.pristine) {
    return null;
  }
  return password && confirmPassword && password.value !== confirmPassword.value ? { 'passwordsMismatch': true } : null;
}

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, QRCodeComponent, RouterLink],
  templateUrl: './register_component.html',
})
export class RegisterComponent {
  registerForm: FormGroup;
  registrationSuccess = false;
  registrationData: RegisterResponse | null = null;
  errorMessage: string | null = null;

  constructor(private fb: FormBuilder, private authService: AuthService) {
    this.registerForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [
        Validators.required,
        Validators.minLength(8),
        // ZMIANA: Dodanie walidatora Regex dla złożoności hasła
        Validators.pattern('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^a-zA-Z\\d]).{8,}$')
      ]],
      confirmPassword: ['', [Validators.required]],
    }, { validators: passwordMatcher });
  }

  onSubmit(): void {
    if (this.registerForm.invalid) {
      return;
    }

    this.errorMessage = null;
    this.authService.register(this.registerForm.value).subscribe({
      next: (response) => {
        this.registrationData = response;
        this.registrationSuccess = true;
      },
      error: (err) => {
        this.errorMessage = 'Wystąpił błąd podczas rejestracji. Spróbuj ponownie.';
        console.error(err);
      }
    });
  }
}