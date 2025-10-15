import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms'; // <-- Importuj ReactiveFormsModule
import { AuthService } from '../Services/auth.service';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-auth',
  standalone: true, // <-- To oznacza, że jest to komponent samodzielny
  imports: [
    CommonModule,
    ReactiveFormsModule, // <-- DODAJ TO TUTAJ, aby używać [formGroup] i formControlName
  ],
  templateUrl: './auth.component.html',
  styleUrls: ['./auth.component.css'],
})
export class AuthComponent implements OnInit {
  // Stan aplikacji - kontroluje, który formularz jest widoczny
  mode: 'login' | 'register' | '2fa' | 'profile' = 'register';

  // Obiekty Reactive Forms
  authForm!: FormGroup;
  otpForm!: FormGroup;

  // Dane stanu po udanych krokach
  userId: string = '';
  qrCodeUri: string = '';
  setupKey: string = '';
  profileMessage: string = '';
  errorMessage: string = '';

  constructor(
    private fb: FormBuilder, // Wstrzyknięcie FormBuilder do tworzenia formularzy
    private authService: AuthService,
  ) {}

  ngOnInit(): void {
    // Sprawdzenie, czy użytkownik jest już zalogowany
    if (this.authService.isLoggedIn()) {
      this.mode = 'profile';
      this.loadProfile();
    } else {
      this.mode = 'register';
    }

    // Inicjalizacja formularza logowania/rejestracji
    this.authForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      // Używamy patternu, aby wymusić te same zasady co .NET Identity
      password: [
        '',
        [Validators.required, Validators.minLength(8), Validators.pattern('(?=.*\\d).{8,}')],
      ],
    });

    // Inicjalizacja formularza 2FA (tylko kod OTP)
    this.otpForm = this.fb.group({
      code: ['', [Validators.required, Validators.pattern('^[0-9]{6}$')]],
    });
  }

  // --- Metody obsługujące przepływ ---

  // Przełącza widok między logowaniem a rejestracją, resetując błędy
  switchMode(newMode: 'login' | 'register'): void {
    this.mode = newMode;
    this.errorMessage = '';
    this.authForm.reset();
  }

  // Używamy jednego handlera, aby obsłużyć rejestrację i logowanie
  onSubmitAuth(): void {
    this.errorMessage = '';
    if (this.authForm.invalid) {
      this.errorMessage = 'Formularz jest niepoprawny. Sprawdź email i hasło.';
      return;
    }

    const { email, password } = this.authForm.value;

    if (this.mode === 'register') {
      this.handleRegistration(email, password);
    } else if (this.mode === 'login') {
      this.handleLogin(email, password);
    }
  }

  private handleRegistration(email: string, password: string): void {
    this.authService.register(email, password).subscribe({
      next: (res) => {
        this.userId = res.userId || this.authService.getUserId() || ''; // Zapis ID po rejestracji
        this.qrCodeUri = res.qrCodeUri;
        this.setupKey = res.setupKey;
        this.mode = '2fa';
        this.otpForm.reset();
        alert('Rejestracja sukces! Zeskanuj kod QR, aby aktywować 2FA.');
      },
      error: (err) => {
        let details = 'Nieznany błąd.';
        if (err.error?.errors) {
          if (Array.isArray(err.error.errors)) {
            details = err.error.errors.join(', ');
          } else if (typeof err.error.errors === 'string') {
            details = err.error.errors;
          } else {
            details = JSON.stringify(err.error.errors);
          }
        }
        this.errorMessage = 'Błąd rejestracji: ' + details;
      },
    });
  }

  private handleLogin(email: string, password: string): void {
    this.authService.login(email, password).subscribe({
      next: (res) => {
        if (res.twoFactorRequired) {
          this.userId = res.userId;
          this.mode = '2fa';
          this.otpForm.reset();
          alert('Hasło poprawne! Wymagany jest kod 2FA.');
        } else {
          // Logowanie natychmiastowe (bez 2FA)
          this.authService.setToken(res.token, res.token.split('_').pop()); // Uproszczone ID
          this.mode = 'profile';
          this.loadProfile();
        }
      },
      error: (err) => {
        this.errorMessage =
          'Logowanie nieudane. Sprawdź dane.' + (err.error.errors?.join(', ') || '');
      },
    });
  }

  // --- Weryfikacja 2FA (Krok 2 Logowania/Aktywacja) ---
  onVerify2FA(): void {
    this.errorMessage = '';
    if (this.otpForm.invalid) {
      this.errorMessage = 'Kod OTP musi składać się z 6 cyfr.';
      return;
    }

    const { code } = this.otpForm.value;

    this.authService.verify2FA(this.userId, code).subscribe({
      next: (res) => {
        // Logowanie zakończone sukcesem po weryfikacji 2FA
        const actualUserId = res.token.split('_').pop(); // Uproszczone pobranie ID z tokena
        this.authService.setToken(res.token, actualUserId);
        this.mode = 'profile';
        this.loadProfile();
        alert('Weryfikacja 2FA udana! Zalogowano.');
      },
      error: (err) => {
        this.errorMessage = 'Błędny kod 2FA. Spróbuj ponownie.';
      },
    });
  }

  // --- Strona Profilowa (Minimalna Funkcjonalność Biznesowa) ---
  loadProfile(): void {
    const currentUserId = this.authService.getUserId();
    if (currentUserId) {
      this.authService.getProfile(currentUserId).subscribe((res) => {
        this.profileMessage = res.message;
      });
    }
  }

  // --- Wylogowanie ---
  onLogout(): void {
    this.authService.logout();
    this.profileMessage = '';
    this.switchMode('login');
  }
}
