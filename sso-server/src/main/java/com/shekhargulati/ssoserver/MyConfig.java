package com.shekhargulati.ssoserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

@Configuration
public class MyConfig {

    @Bean
    public PasswordEncoder passwordEncoder(){
//    	return new BCryptPasswordEncoder();
        return new SCryptPasswordEncoder();
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
}
