package com.example.auth_server.controller;

import com.example.auth_server.model.Credential;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.sql.Date;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Map;

@RestController
@RequestMapping("/login")
public class AuthController {

    @Value("${jwt.secret}")
    private String secret;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping
    public String authenticate(@RequestParam String username, @RequestParam String password) {
        System.out.println("authenticate with GET");
        return getToken(username, password);
    }

    @PostMapping
    public String authenticate(@RequestBody Credential credential) {
        System.out.println("authenticate with POST");
        return getToken(credential.getUsername(), credential.getPassword());
    }

    private String getToken(String username, String password) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(username, password);

        try {
            Authentication authentication = authenticationManager.authenticate(authToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) authentication.getAuthorities();
            StringBuffer stringBuffer = new StringBuffer();
            stringBuffer.append("[");

            GrantedAuthority[] grantedAuthorities = authorities.toArray(new GrantedAuthority[0]);
            for(int i = 0; i < grantedAuthorities.length ; i ++) {
                stringBuffer.append(grantedAuthorities[i].getAuthority());

                if(i < grantedAuthorities.length - 1) {
                    stringBuffer.append(",");
                }
            }

            stringBuffer.append("]");

            return Jwts.builder()
                    .claim("username", username)
                    .claim("roles", stringBuffer.toString())
                    .setSubject(username)
                    .setIssuedAt(Date.from(Instant.now()))
                    .setExpiration(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                    .signWith(SignatureAlgorithm.HS256,secret).compact();
        } catch (BadCredentialsException ex) {
            throw new BadCredentialsException("Invalid username or password");
        }
    }

}
