package com.manoj.spring.security.firstspringsecurityapp.security;

import com.manoj.spring.security.firstspringsecurityapp.security.custom.MySecurityFilter;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class MySecurityConfig {


    // expose bean called UserDetailsService so that Spring will run use it in the authentication filter chain
   /* @Bean
    public UserDetailsService userDetailsService(){

        // creating our own User details manager
        InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();

        // Creating user with details
        UserDetails userDetails = User.withUsername("Tom")
                .password(passwordEncoder().encode("Cruise") )
                .authorities("READ")
                .build();

        // assigning the new user to our own user details manager
        userDetailsService.createUser(userDetails);

        // return our own User details manager
        return userDetailsService;
    }*/

   /*
    Bean of BCryptPasswordEncoder to encode the passcode in the in-memory database.
    when the request comes in Spring Security will look at this bean and it will use this bean on the incoming password
    and then compare the passwords.
    */
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        /*  To enable form login
            Typically we enable form login for web applications, not for RESTful applications
        */
       // httpSecurity.formLogin();

        httpSecurity.httpBasic(); // Authenticate with Http Basic authentication

        //httpSecurity.authorizeHttpRequests().anyRequest().authenticated(); // Authorize any request that is authenticated.

        // In this, we are saying authorize requests that are matching "/hello" URL.
        httpSecurity.authorizeHttpRequests().requestMatchers("/hello").authenticated();

        // configure Security filter
        httpSecurity.addFilterBefore(new MySecurityFilter(), BasicAuthenticationFilter.class);

        return httpSecurity.build();

    }

}
