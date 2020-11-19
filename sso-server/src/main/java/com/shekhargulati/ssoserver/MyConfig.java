package com.shekhargulati.ssoserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
public class MyConfig {

    @Bean
    public PasswordEncoder passwordEncoder(){
//    	return new BCryptPasswordEncoder();
//        return new SCryptPasswordEncoder();
        return new MySha256PasswordEncoder();
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public MyUserDetailService myUserDetailService() {
    	return new MyUserDetailService();
    }

    @Bean
    public AuthenticationProvider myAuthenticationProvider() {
    	DaoAuthenticationProvider dap = new DaoAuthenticationProvider();
    	dap.setPasswordEncoder(this.passwordEncoder());
    	dap.setUserDetailsService(this.myUserDetailService());

    	return dap;
    }


    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("mysignkey");
        return converter;
    }


    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }
}
