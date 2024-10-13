package io.dumerz.secured.controller;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/")
    public String home(Model model, Authentication authentication) {
        if (authentication != null) {
            String username = authentication.getName(); // Get the username
            Collection<? extends GrantedAuthority> roles = authentication.getAuthorities(); // Get roles

            model.addAttribute("username", username);
            model.addAttribute("roles", roles);
        }
        return "welcome"; // Return your Thymeleaf template
    }
 
    @GetMapping("/admin")
    public String user() {
        return "admin.html";
    }
 
    @GetMapping("/user")
    public String basic() {
        return "user.html";
    }
 
    @GetMapping("/login")
    public String login() {
        return "login.html";
    }
}
