package com.shekhargulati.app1;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


import lombok.extern.slf4j.Slf4j;

public class App1WebSecurity{

}


//@Slf4j
//@EnableWebSecurity
//@Configuration
//@Order(Ordered.LOWEST_PRECEDENCE - 5 - 10)
//public class App1WebSecurity extends WebSecurityConfigurerAdapter {
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.antMatcher("/**")
//        .authorizeRequests()
//        .antMatchers("/apple/hello").hasRole("APPLE")
//        .antMatchers("/pear/hello").hasRole("PEAR")
//        .anyRequest().authenticated()
//        ;
//    }
//}
