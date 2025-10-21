import { Routes } from '@angular/router';
import { RegisterComponent } from './register_component/register_component';
import { LoginComponent } from './login_component/login_component';
import { DashboardComponent } from '../app/dashboard_component/dashboard_component';
import { authGuard } from './guards/auth.guard';
import { LoginSuccessComponent } from './extended_login_component/login_success_component/login_success_component';
import { LoginFailedComponent } from './extended_login_component/login_failed_component/login_failed_component';


export const routes: Routes = [
    { path: 'register', component: RegisterComponent },
    { path: 'login', component: LoginComponent },
    { path: 'login-success', component: LoginSuccessComponent },
    { path: 'login-failed', component: LoginFailedComponent },
    { 
        path: 'dashboard', 
        component: DashboardComponent,
        canActivate: [authGuard] // Ochrona tej ścieżki
    },
    
    // Przekierowanie domyślnej ścieżki na logowanie
    { path: '', redirectTo: '/login', pathMatch: 'full' }, 
    // Obsługa nieznanych ścieżek
    { path: '**', redirectTo: '/login' } 
];
