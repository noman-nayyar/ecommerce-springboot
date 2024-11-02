package com.example.ecommerce.security;

import com.example.ecommerce.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/* Purpose: This filter intercepts each HTTP request
            , validates the JWT token
            , and sets the security context for authenticated requests.
 */

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserService userService;

    /* Dependency injection of JwtUtil for JWT handling
        and UserService to retrieve user information.
     */
    @Autowired
    public JwtFilter(JwtUtil jwtUtil, UserService userService) {
        this.jwtUtil = jwtUtil;
        this.userService = userService;
    }

    // OncePerRequestFilter ensures it runs once per request.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        /* Retrieves the Authorization header from the incoming request.
            Initializes username and token variables.
         */
        String authHeader = request.getHeader("Authorization");

        String username = null;
        String token = null;

        /* Check for Bearer token in Authorization header
        If the authorization header starts with “Bearer “, the token is extracted
        , and the username is retrieved using jwtUtil.
         */
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            username = jwtUtil.getUsernameFromToken(token);
        }

        /* Validate token and set authentication context
            If a valid token is found and the security context is unauthenticated, the filter:

                •	Loads user details,
                •	Creates an authentication token,
                •	Sets it in the security context,
                •	Continues with the filter chain.
         */
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (jwtUtil.validateToken(token)) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userService.loadUserByUsername(username), null, userService.loadUserByUsername(username).getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        chain.doFilter(request, response);
    }
}