import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isLoggedIn()) {
    return true; // Użytkownik jest zalogowany, zezwól na dostęp
  }

  // Użytkownik nie jest zalogowany, przekieruj do strony logowania
  return router.parseUrl('/login');
};