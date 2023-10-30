package com.cybage.Platform.web;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.cybage.Platform.dto.AuthRequest;
import com.cybage.Platform.dto.AuthorityDTO;
import com.cybage.Platform.dto.UserDTO;
import com.cybage.Platform.service.JWTService;
import com.fasterxml.jackson.core.JsonProcessingException;

@RestController
@RequestMapping("/api/v1/user")
public class PlatformController {
	
	@Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private JWTService jwtService;
    
    @Autowired
    RestTemplate restTemplate;
    
    @Autowired
    private InMemoryUserDetailsManager userDetailsService;
	
    @PostMapping(value = {"/authenticate", "/login"})
    public UserDTO authenticateAndGetToken(AuthRequest authRequest) throws JsonProcessingException {
    	Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if (authentication.isAuthenticated()) {
        	
			
			  HttpHeaders headers = new HttpHeaders();
				
			  headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			  
					
				MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
				map.add("username", authRequest.getUsername());
				map.add("password", authRequest.getPassword());

				HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<MultiValueMap<String, String>>(map,
						headers);
					 
            ResponseEntity<String> firewallResponse=restTemplate.exchange(
               "http://cyb.platform/FirewallApp/login", HttpMethod.POST, entity, String.class);
                       
            String firewallToken=firewallResponse.getBody();
            ResponseEntity<String> switchResponse=restTemplate.exchange(
                    "http://cyb.platform/SwitchApp/login", HttpMethod.POST, entity, String.class);
            String switchToken=switchResponse.getBody();
                
            
            UserDTO userDTO=mapUserAndReturnJwtToken(authentication, true);
            userDTO.setSwitchToken(switchToken);
            userDTO.setFirewallToken(firewallToken);
            
            return userDTO;
            
        } else {
            throw new UsernameNotFoundException("invalid user request !");
        }
        
    }
	
	private UserDTO mapUserAndReturnJwtToken(Authentication authentication, boolean generateToken)
	{
		
		UserDetails customUserDetails = (UserDetails)authentication.getPrincipal();
		
		UserDTO userDTO = new UserDTO();
		userDTO.setUsername(customUserDetails.getUsername());
		userDTO.setEnabled(customUserDetails.isEnabled());
		userDTO.setAccountNonExpired(customUserDetails.isAccountNonExpired());
		userDTO.setAccountNonLocked(customUserDetails.isAccountNonLocked());
		userDTO.setCredentialsNonExpired(customUserDetails.isCredentialsNonExpired());
		userDTO.setAuthorities(mapAuthorities(customUserDetails.getAuthorities()));
		if (generateToken)
		{
			String jwtToken= jwtService.generateToken(customUserDetails.getUsername());
			userDTO.setToken(jwtToken);
			userDTO.setTimeBeforeExpiration(jwtService.extractExpiration(jwtToken));
		}
		return userDTO;
	}

	private Set<AuthorityDTO> mapAuthorities(Collection<? extends GrantedAuthority> authorities)
	{
		Set<AuthorityDTO> authorityDTOList = new HashSet<>();
		authorities.forEach(grantedAuthority -> authorityDTOList.add(new AuthorityDTO(grantedAuthority.getAuthority())));
		return authorityDTOList;
	}
	
	@RequestMapping("/platform/version")
    String hello( String name) {
        return "Platfrom Version 1.0";
    }
	
	@GetMapping(value = {"/get_logged_in_user", "/home"})
	public UserDTO getLoggedInUser()
	{
		return mapUserAndReturnJwtToken(SecurityContextHolder.getContext().getAuthentication(), false);
	}

	@GetMapping("/logout")
	public void logout(HttpServletRequest request)
	{
		SecurityContextHolder.getContext().setAuthentication(null);
		try
		{
			request.logout();
		}
		catch (ServletException e)
		{
			e.printStackTrace();
		}

}
	
	@RequestMapping(value = "/firewallVersion")
    public String getFirewallVersion(@RequestParam(value = "token") String token) throws JsonProcessingException {
    	
        	
			
			  HttpHeaders headers = new HttpHeaders();
				
			  headers.set("Authorization", "Bearer "+token);
			  
					
				MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
				

				HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<MultiValueMap<String, String>>(map,
						headers);
					 
            ResponseEntity<String> firewallResponse=restTemplate.exchange(
               "http://cyb.platform/FirewallApp/firewall/version", HttpMethod.GET, entity, String.class);
                       
            
            
            return firewallResponse.getBody();
            
        
    }
	
}
