package com.cybage.FirewallApplication.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class SimpleController {

    @Value("${spring.application.name}")
    String appName;
        
 // Login form
    @RequestMapping("/login.html")
    public String login() {
      return "login.html";
    }
    

    // Login form with error
    @RequestMapping("/login-error.html")
    public String loginError(Model model) {
      model.addAttribute("loginError", true);
      return "login.html";
    }

    @RequestMapping("/firewall")
    public String homePage(Model model) {
        model.addAttribute("appName", appName);
        return "home";
    }
}
