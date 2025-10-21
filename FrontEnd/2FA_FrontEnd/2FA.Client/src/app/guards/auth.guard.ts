import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth';
import { map, catchError, of } from 'rxjs';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // Jeśli użytkownik jest już zalogowany (nawigacja wewnątrz aplikacji), przepuść
  if (authService.isLoggedIn()) {
    return true;
  }

  // Jeśli nie (np. po odświeżeniu strony), sprawdź status na serwerze
  return authService.checkAuthStatus().pipe(
    map(isLoggedIn => {
      if (isLoggedIn) {
        return true;
      }
      // Jeśli serwer potwierdzi brak logowania, przekieruj
      return router.parseUrl('/login');
    }),
    catchError(() => {
      // W razie błędu sieciowego również przekieruj
      return of(router.parseUrl('/login'));
    })
  );
};