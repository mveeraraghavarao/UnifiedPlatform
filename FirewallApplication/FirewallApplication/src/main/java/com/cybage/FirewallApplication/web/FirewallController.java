package com.cybage.FirewallApplication.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cybage.FirewallApplication.dto.AuthRequest;
import com.cybage.FirewallApplication.service.JWTService;

@RestController
@CrossOrigin
public class FirewallController {
	
	@Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private JWTService jwtService;
	
	@PostMapping("/login")
    public String authenticateAndGetToken(AuthRequest authRequest) {
    	Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if (authentication.isAuthenticated()) {
            return jwtService.generateToken(authRequest.getUsername());
            
			/*
			 * Cookie cookie = new Cookie("login_token",token);
			 * 
			 * cookie.setPath("/"); cookie.setMaxAge(Integer.MAX_VALUE);
			 * 
			 * res.addCookie(cookie);
			 * 
			 * return "redirect:/home";
			 */
            
        } else {
            throw new UsernameNotFoundException("invalid user request !");
        }
        
        

        
        
    }
	
	@RequestMapping("/firewall/version")
    String hello( String name) {
        return "Gen 7";
    }

}
