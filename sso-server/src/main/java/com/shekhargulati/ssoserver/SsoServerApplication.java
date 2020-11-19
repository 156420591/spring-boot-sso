package com.shekhargulati.ssoserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

@SpringBootApplication
@EnableResourceServer
public class SsoServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsoServerApplication.class, args);
    }

    @Configuration
    @Order(1)
    protected static class LoginConfig extends WebSecurityConfigurerAdapter {
//    	@Autowired
//    	PasswordEncoder passwordEncoder;
//    	@Autowired
//    	MyUserDetailService myUserDetailService;

    	@Autowired
    	AuthenticationProvider myAuthenticationProvider;

    	@Bean
    	@Override
		protected AuthenticationManager authenticationManager() throws Exception {
			return super.authenticationManager();
		}

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.requestMatchers()
                    .antMatchers("/login", "/oauth/authorize")
                    .and()
                    .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .formLogin().permitAll();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        	//understand AuthenticationManager -> ProviderManager -> AuthenticationProvider
        	auth.authenticationProvider(this.myAuthenticationProvider);

        	//equal to this
//        	auth.userDetailsService(this.myUserDetailService).passwordEncoder(this.passwordEncoder);

//        	auth.userDetailsService(this.myUserDetailService);

//            auth.inMemoryAuthentication()
//                    .withUser("user")
//                    .password(passwordEncoder.encode("password"))
//                    .roles("USER");
        }

    }

    //understanding grant type
    //https://oauth.net/2/grant-types/

    //https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/  当resource server usage
    //curl -u foo:bar -X POST http://localhost:8080/sso-server/oauth/token -H 'Content-Type: application/x-www-form-urlencoded'  -d 'grant_type=client_credentials&client_id=foo&&client_secret=bar'


    //https://www.oauth.com/oauth2-servers/access-tokens/password-grant/ password grant type usage
    //https://www.techgeeknext.com/spring-boot-security/springboot-oauth2-password-grant

    @Configuration
    @EnableAuthorizationServer
    //https://www.techgeeknext.com/spring-boot-security/springboot-oauth2-password-grant
    //@EnableAuthorizationServer Authorization Server exposes endpoints for requesting access token (/oauth/token), checking the access token (/oauth/check_token), authorizing the client, etc
    protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {

    	@Autowired
    	private PasswordEncoder passwordEncoder;

    	//这两步可以把普通的access token换成jwt token
    	@Autowired
    	private TokenStore tokenStore;
    	@Autowired
    	JwtAccessTokenConverter jwtAccessTokenConverter;

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.inMemory()
                    .withClient("foo")
                    .secret(passwordEncoder.encode("bar"))
//                    .authorizedGrantTypes("authorization_code", "refresh_token", "password")
//                    .scopes("user_info")


                  .authorizedGrantTypes("authorization_code", "refresh_token", "password", "client_credentials")
                    .scopes("all")

                    .autoApprove(true)
                    .accessTokenValiditySeconds(60)
                    .refreshTokenValiditySeconds(60)
                    ;
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
            oauthServer
                    .tokenKeyAccess("permitAll()")
                    .checkTokenAccess("isAuthenticated()")
                    .allowFormAuthenticationForClients();
        }


    	@Override
    	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            DefaultTokenServices tokenServices = new DefaultTokenServices();
            tokenServices.setTokenStore(this.tokenStore);
            tokenServices.setSupportRefreshToken(true);
            tokenServices.setTokenEnhancer(this.jwtAccessTokenConverter);

            tokenServices.setAccessTokenValiditySeconds(60);
            tokenServices.setRefreshTokenValiditySeconds(60);


            tokenServices.setClientDetailsService(endpoints.getClientDetailsService());

            endpoints.tokenServices(tokenServices);
    	}
    }
}
