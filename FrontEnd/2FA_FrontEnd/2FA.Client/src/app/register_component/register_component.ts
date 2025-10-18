import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { QRCodeModule } from 'angularx-qrcode'; 
import { AuthService } from '../services/auth';
import { RegisterResponse } from '../auth_compomnent/auth.models';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, QRCodeModule],
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
      password: ['', [Validators.required, Validators.minLength(6)]],
    });
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