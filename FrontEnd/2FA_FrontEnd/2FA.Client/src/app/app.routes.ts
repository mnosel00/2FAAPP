import { Routes } from '@angular/router';
import { RegisterComponent } from './register_component/register_component';
import { LoginComponent } from './login_component/login_component';
import { DashboardComponent } from '../app/dashboard_component/dashboard_component';
import { authGuard } from './guards/auth.guard';

export const routes: Routes = [
    { path: 'register', component: RegisterComponent },
    { path: 'login', component: LoginComponent },
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
