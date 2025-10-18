import { Component, signal } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { LoginComponent } from './login_component/login_component';
import { RegisterComponent } from './register_component/register_component';


@Component({
  selector: 'app-root',
  imports: [
    LoginComponent,
    RegisterComponent,
    RouterOutlet,
  ],
  templateUrl: './app.html',
  styleUrl: './app.scss'
})
export class App {
  protected readonly title = signal('2FA.Client');
}
