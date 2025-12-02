import { HttpInterceptorFn } from '@angular/common/http';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  // Klonujemy każde żądanie i dodajemy flagę withCredentials
  // To mówi przeglądarce: "wyślij ciasteczka razem z tym żądaniem"
  const clonedRequest = req.clone({
    withCredentials: true
  });

  return next(clonedRequest);
};