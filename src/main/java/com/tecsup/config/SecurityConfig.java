package com.tecsup.config;

import com.tecsup.jwt.JwtAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthFilter jwtAuthFilter;

    // ENCRIPTAR PASSWORD
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // AUTHENTICATION MANAGER
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig)
            throws Exception {
        return authConfig.getAuthenticationManager();
    }

    // CONFIGURACION SECURITY
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                // DESACTIVAR CSRF
                .csrf(csrf -> csrf.disable())

                // NO USAR SESIONES
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // RUTAS PUBLICAS Y PRIVADAS
                .authorizeHttpRequests(auth -> auth

                        // PUBLICAS
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/test/all").permitAll()   // CAMBIO

                        // ADMIN
                        .requestMatchers("/api/test/admin").hasRole("ADMIN")

                        // MODERATOR
                        .requestMatchers("/api/test/mod").hasRole("MODERATOR")

                        // USER
                        .requestMatchers("/api/test/user").hasAnyRole("USER", "ADMIN")

                        // TODAS LAS DEMAS
                        .anyRequest().authenticated()
                );

        // FILTRO JWT
        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}