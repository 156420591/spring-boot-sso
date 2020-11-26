package com.shekhargulati.app1.standalonesample;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;


//https://docs.spring.io/spring-security/site/docs/3.0.x/reference/technical-overview.html#d0e1543
//如何使用AuthenticationManager Authentication(spring内部是如何authenticate的)

class SampleAuthenticationManager implements AuthenticationManager{
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        List<GrantedAuthority> myau = new ArrayList<>();
        myau.add(new SimpleGrantedAuthority("ROLE_USER"));

        //name == password, password is always plaintext, while we store hashed password to db, so we can equal as hashed(password)==db_password
        if(authentication.getName().equals(authentication.getCredentials())) {
            return new UsernamePasswordAuthenticationToken(authentication.getName(), authentication.getCredentials(), myau);
        }
        throw new BadCredentialsException("username should equal to password");
    }
}

public class AuthenticationSample1 {

    public static void main(String[] args) throws Exception {

        AuthenticationManager am = new SampleAuthenticationManager();

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

        while(true) {
            System.out.println("Please enter your username:");
            String name = in.readLine();
            System.out.println("Please enter your password:");
            String password = in.readLine();
            try {
                Authentication request = new UsernamePasswordAuthenticationToken(name, password);
                Authentication result = am.authenticate(request);
                SecurityContextHolder.getContext().setAuthentication(result);
                break;
            } catch(AuthenticationException e) {
                System.out.println("Authentication failed: " + e.getMessage());
            }
        }
        System.out.println("Successfully authenticated. Security context contains: " +
                SecurityContextHolder.getContext().getAuthentication());

    }

}
