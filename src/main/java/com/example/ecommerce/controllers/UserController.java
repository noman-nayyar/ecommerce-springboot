package com.example.ecommerce.controllers;

import com.example.ecommerce.models.Role;
import com.example.ecommerce.models.User;
import com.example.ecommerce.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public String register(@RequestBody User user) {
        userService.registerUser(user.getUsername(), user.getEmail(), user.getPassword(), Role.CUSTOMER);
        return "User registered successfully!";
    }

    @PostMapping("/register/admin")
    public String registerAdmin(@RequestBody User user) {
        userService.registerUser(user.getUsername(), user.getEmail(), user.getPassword(), Role.ADMIN);
        return "Admin registered successfully!";
    }

    // Get User Profile
    @GetMapping("/user/profile")
    // Access URL: http://localhost:8080/api/user/profile?username=customer1
    public ResponseEntity<?> getProfile() {
        // Get the authenticated user's username
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String authenticatedUsername = authentication.getName();

        // Fetch the user profile of the authenticated user only
        User user = userService.findByUsername(authenticatedUsername);
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

    // Admin Dashboard
    @GetMapping("/admin/dashboard")
    public ResponseEntity<String> adminDashboard() {
        return ResponseEntity.ok("Welcome to the Admin Dashboard!");
    }

    // Get All Users (Admin Functionality)
    @GetMapping("/admin/users")
    public List<User> getAllUsers() {
        return userService.getAllUsers(); // Assume this method exists in UserService
    }

}