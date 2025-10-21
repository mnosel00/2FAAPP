import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login-success',
  standalone: true,
  imports: [],
  template: '<p>Logowanie pomyślne! Trwa przekierowywanie...</p>',
})
export class LoginSuccessComponent implements OnInit {
  constructor(private router: Router) {}

  ngOnInit(): void {
    // Po pomyślnym zalogowaniu przez Google, przekieruj na dashboard
    this.router.navigate(['/dashboard']);
  }
}