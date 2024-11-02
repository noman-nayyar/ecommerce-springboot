package com.example.ecommerce.services;

import com.example.ecommerce.models.Role;
import com.example.ecommerce.models.User;
import com.example.ecommerce.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

/*
The UserService class is a service layer for managing user-related operations in the application.
    	•	This includes registering users,
    	•	finding users by username,
    	•	converting user details to Spring Security’s UserDetails format for authentication,
    	•	and listing all users.
    	•	@Service: Declares this as a Spring-managed service, enabling dependency injection and transactional capabilities.
	    •	UserDetailsService: Implements Spring Security’s interface, allowing it to load user-specific data needed during authentication.
 */

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /*
        Registers a new user with a hashed password.
     */
    public User registerUser(String username, String email, String password, Role role) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRoles(Collections.singleton(role));
        return userRepository.save(user);
    }

    /*
        Finds a user by username, returning null if the user is not found.
        •	userRepository.findByUsername(username) queries the database for a user by username.
        •	.orElse(null); returns the user if found, or null otherwise.
            This uses Java’s Optional for handling potentially missing data.
     */
    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    /*
        Loads a user by username for Spring Security authentication,
        throwing an exception if the user is not found.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Convert our custom User object to Spring Security's UserDetails
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword())
                // Converts the user’s roles from a Set<Role> to String[] for Spring Security.
                .roles(user.getRoles().stream().map(Role::name).toArray(String[]::new))
                .build();
    }

    /*
        Retrieves all users from the database.
     */
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}