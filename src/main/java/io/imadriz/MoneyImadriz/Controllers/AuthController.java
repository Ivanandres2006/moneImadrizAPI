package io.imadriz.MoneyImadriz.Controllers;

import io.imadriz.MoneyImadriz.Payloads.request.LoginRequest;
import io.imadriz.MoneyImadriz.Payloads.request.SignupRequest;
import io.imadriz.MoneyImadriz.Services.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody final LoginRequest loginRequest) {
        return authService.authUser(loginRequest);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody final SignupRequest signupRequest) {
        return authService.createUser(signupRequest);
    }
}
