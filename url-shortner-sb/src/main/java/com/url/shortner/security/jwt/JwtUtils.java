package com.url.shortner.security.jwt;

import com.url.shortner.service.UserDetailsImpl;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;

import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

//request to authorized endpoint need to parse the token via authorization header
public class JwtUtils {
    //Authorization -> Bearer <TOKEN>

    //injectable -> application.properties
    @Value("$jwt.secret")
    private String jwtSecret;

    @Value("$jwt.expiration")
    private int jwtExpirationMs;

    //extract token from header
    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            //exclude "Bearer" from the token
            return bearerToken.substring(7);
        }
        return null;
    }

    //generate the token
    public String generateToken(UserDetailsImpl userDetails) {
        String username = userDetails.getUsername();
        String roles = userDetails.getAuthorities().stream()
                .map(authority -> authority.getAuthority()).collect(Collectors.joining(","));
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(new Date())
                //expiration Date in 2 days
                .expiration(new Date((new Date().getTime() + jwtExpirationMs)))
                .signWith(key())
                .compact();
    }

    private Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }
}
