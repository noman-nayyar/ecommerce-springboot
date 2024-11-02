package com.example.ecommerce.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

/*
Purpose: This utility class manages JWT (JSON Web Token) operations
        , including generating tokens
        , validating them
        , extracting usernames from tokens.
        The @Component annotation registers this class as a Spring bean, so it can be auto-wired.
 */

@Component
public class JwtUtil {

    /* These fields store the JWT secret key and expiration time (in milliseconds)
    , loaded from the application’s configuration (like application.properties).
     */
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expirationMs}")
    private int jwtExpirationMs;

    /* The getSigningKey() method decodes the base64 secret
     and generates a signing key for HMAC SHA-256 signing.
     */
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /* Generate JWT Token with
    	•	Subject: The username (used to identify the user).
	    •	Issued Date: Current time when the token was created.
	    •	Expiration Date: Current time + the specified JWT expiry.
	    •	Signing Key: Uses getSigningKey() to sign the token securely.
     */
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(getSigningKey())  // Use getSigningKey() for signing
                .compact();
    }

    /* Validate JWT Token
        checks the token’s integrity. If valid, it returns true; otherwise, false.
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /* Extract Username from JWT Token
        parses the token
        , retrieves the claims
        , and extracts the username from the subject field.
     */
    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
        return claims.getSubject();
    }
}