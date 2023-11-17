package com.example.demo.controller;

import com.example.demo.utils.JwtUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(value = "home")
public class HomeController {
    @GetMapping(value = "health")
    public String index() {

        return ":)";
    }

    @GetMapping(value = "resource")
    public String resource(HttpServletRequest httpRequest) {
        String token = httpRequest.getHeader("Authorization");
        if (null == token) {
            return "Your token is null.";
        }

        try {
            JwtUtils jwt = new JwtUtils();
            String userName = jwt.getUserNameFromToken(token);
            return "You can access resource," + userName;
        } catch (Exception e) {
            return "Your token is invalid:" + e.getMessage();
        }
    }
}
