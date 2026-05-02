package com.example.loanmanagement.security;

import java.security.Key;
import java.util.Date;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

    private final String SECRET =
            "mysecretkeymysecretkeymysecretkey";

    private final long EXPIRATION =
            1000 * 60 * 60 * 10; // 10 hours

    private final Key key =
            Keys.hmacShaKeyFor(
                    SECRET.getBytes()
            );

    public String generateToken(
            String email,
            String role
    ) {

        return Jwts.builder()
                .setSubject(email)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(
                        new Date(
                                System.currentTimeMillis()
                                        + EXPIRATION
                        )
                )
                .signWith(key)
                .compact();
    }

    public String extractEmail(String token) {

        return extractClaims(token)
                .getSubject();
    }

    public boolean validateToken(String token) {

        try {

            extractClaims(token);

            return true;

        } catch (Exception e) {

            return false;
        }
    }

    private Claims extractClaims(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}