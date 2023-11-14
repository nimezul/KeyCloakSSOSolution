package com.example.demo.controller;

import com.example.demo.utils.SamlException;
import com.example.demo.utils.SamlUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping(value = "sso")
public class SsoController {

    SamlUtils samlUtil;

    @GetMapping("login")
    public void login(HttpServletResponse response) throws SamlException, IOException {
        samlUtil = new SamlUtils();
        String url = samlUtil.getRedirectUrl(response, "http://localhost:8088/home/index");
        response.sendRedirect(url);
    }

    @PostMapping("acs")
    public String acs(@RequestParam(name = "SAMLResponse") String samlResponse, @RequestParam(name = "RelayState") String redirectedURL, HttpServletResponse response) throws SamlException {
        return "User " + samlUtil.getNameID(samlResponse) + " Login success, will redirect to " + redirectedURL;
    }
}
