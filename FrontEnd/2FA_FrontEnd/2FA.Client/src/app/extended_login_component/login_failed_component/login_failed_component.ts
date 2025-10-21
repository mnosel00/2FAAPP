import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-login-failed',
  standalone: true,
  imports: [RouterLink],
  template: `
    <div class="text-center">
      <h2>Logowanie nie powiodło się</h2>
      <p>Wystąpił błąd podczas próby logowania przez Google. Spróbuj ponownie.</p>
      <a routerLink="/login" class="btn btn-primary">Powrót do logowania</a>
    </div>
  `,
})
export class LoginFailedComponent {}