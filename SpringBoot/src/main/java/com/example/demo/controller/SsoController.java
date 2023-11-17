package com.example.demo.controller;

import com.example.demo.utils.JwtUtils;
import com.example.demo.utils.SamlException;
import com.example.demo.utils.SamlUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

@RestController
@RequestMapping(value = "sso")
public class SsoController {
    SamlUtils samlUtil;

    @GetMapping("login")
    public void login(HttpServletResponse response, String redirectedURL) throws SamlException, IOException {
        samlUtil = new SamlUtils();
        String url = samlUtil.getRedirectUrl(response, redirectedURL == null ? "http://localhost:8088" : redirectedURL);

        response.sendRedirect(url);
    }

    @PostMapping("acs")
    public void acs(@RequestParam(name = "SAMLResponse") String samlResponse, @RequestParam(name = "RelayState") String redirectedURL, HttpServletResponse response) throws SamlException, IOException {
        String userName = samlUtil.getNameID(samlResponse);
        String token = new JwtUtils().generateToken(userName);

        //encode token
        String encodeStr = URLEncoder.encode(token, "utf-8");
        String encodeValue = encodeStr.replaceAll("\\+", "%20");

        //add encode token to cookie
        Cookie cookie = new Cookie("token", encodeValue);
        cookie.setPath("/");
        response.addCookie(cookie);

        response.sendRedirect(redirectedURL);
    }
}
