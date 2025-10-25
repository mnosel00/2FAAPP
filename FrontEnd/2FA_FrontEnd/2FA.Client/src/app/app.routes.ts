import { Routes } from '@angular/router';
import { RegisterComponent } from './register_component/register_component';
import { LoginComponent } from './login_component/login_component';
import { DashboardComponent } from './dashboard_component/dashboard_component'; // ZMIANA: Poprawiona ścieżka importu dla DashboardComponent
import { authGuard } from './guards/auth.guard';
import { LoginSuccessComponent } from './extended_login_component/login_success_component/login_success_component';
import { LoginFailedComponent } from './extended_login_component/login_failed_component/login_failed_component';
import { ResetPasswordComponent } from './reset_password_component/reset_password_component'; // ZMIANA: Import nowego komponentu

export const routes: Routes = [
    { path: 'register', component: RegisterComponent },
    { path: 'login', component: LoginComponent },
    { path: 'reset-password', component: ResetPasswordComponent },
    { path: 'login-success', component: LoginSuccessComponent },
    { path: 'login-failed', component: LoginFailedComponent },
    { 
        path: 'dashboard', 
        component: DashboardComponent, // Ta linia jest teraz poprawna dzięki dobremu importowi
        canActivate: [authGuard]
    },
    { path: '', redirectTo: '/login', pathMatch: 'full' }, 
    { path: '**', redirectTo: '/login' } 
];
