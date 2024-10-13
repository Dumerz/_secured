package io.dumerz.secured.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.core.userdetails.User;
 
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {
 
    @Bean
    public SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Disable CSRF for simplicity; adjust as needed
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/user").hasAnyRole("USER","ADMIN") // any roles for /user routes
                .requestMatchers("/admin").hasRole("ADMIN") // Only admin role for /admin routes
                .requestMatchers("/login").authenticated()
                .requestMatchers("/").authenticated()) //Any authenticated user 
            .formLogin(form -> form
                .loginPage("/login") // Custom login page
                .permitAll()) // Allow everyone to see the login page
            .logout(logout -> logout
                .permitAll()); // Enable logout functionality;
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Password encoder
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        return new InMemoryUserDetailsManager(
            User.withUsername("admin")
                .password(passwordEncoder().encode("adminpass")) // Admin user
                .roles("ADMIN", "USER")
                .build(),
            User.withUsername("user")
                .password(passwordEncoder().encode("userpass")) // Basic user
                .roles("USER")
                .build()
        );
    }

    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
    }
}