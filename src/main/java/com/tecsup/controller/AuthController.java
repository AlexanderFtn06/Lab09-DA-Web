package com.tecsup.controller;

import com.tecsup.dto.*;
import com.tecsup.entity.Role;
import com.tecsup.entity.User;
import com.tecsup.jwt.JwtUtils;
import com.tecsup.repository.RoleRepository;
import com.tecsup.repository.UserRepository;
import com.tecsup.service.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;

    // REGISTRO
    @Transactional
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signUpRequest) {

        // Validar username
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: Username ya existe"));
        }

        // Validar email
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: Email ya existe"));
        }

        // Crear usuario
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());

        // Encriptar password
        user.setPassword(encoder.encode(signUpRequest.getPassword()));

        // Roles
        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        // Si no envía roles
        if (strRoles == null || strRoles.isEmpty()) {
            roles.add(findRole("USER"));
        } else {
            strRoles.forEach(role -> {
                switch (role.toUpperCase()) {
                    case "ADMIN":
                        roles.add(findRole("ADMIN"));
                        break;
                    case "MODERATOR":
                        roles.add(findRole("MODERATOR"));
                        break;
                    default:
                        roles.add(findRole("USER"));
                }
            });
        }

        // Asignar roles y guardar
        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("Usuario registrado correctamente"));
    }


    // LOGIN JWT
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

        // Autenticar usuario
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(), loginRequest.getPassword()));

        // Guardar autenticación
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generar JWT
        String jwt = jwtUtils.generateJwtToken(authentication);

        // Obtener usuario autenticado
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        // Obtener roles
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // Retornar token JWT
        return ResponseEntity.ok(new JwtResponse(
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                jwt,
                roles));
    }

    private Role findRole(String name) {
        return roleRepository.findByName(name)
                .orElseThrow(() -> new RuntimeException("Rol " + name + " no encontrado"));
    }
}