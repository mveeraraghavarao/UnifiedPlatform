package com.cybage.Platform.web.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;

import com.cybage.Platform.filter.JwtAuthFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Autowired
	JwtAuthFilter authFilter;
	
	
	@Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.withUsername("user")
            .password(passwordEncoder().encode("password"))
            .roles("USER")
            .build();

        UserDetails admin = User.withUsername("admin")
            .password(passwordEncoder().encode("admin"))
            .roles("USER", "ADMIN")
            .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    	http.cors().and().csrf().
    	disable().
    	authorizeHttpRequests()
    	.antMatchers("/api/v1/user/login/", "/api/v1/user/authenticate/", "/api/v1/user/logout/")
        .permitAll()
        .anyRequest()
        .authenticated()
	    .and().httpBasic()
				 
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
        .authenticationManager(authManager(http))
        .logout().invalidateHttpSession(true).clearAuthentication(true);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        return encoder;
    }
    
    
    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = 
          http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailsService());
        
        return authenticationManagerBuilder.build();
    }
    
    @Bean
    public RestTemplate getRestTemplate() {
       return new RestTemplate();
    }

}
