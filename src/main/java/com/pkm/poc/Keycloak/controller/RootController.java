package com.pkm.poc.Keycloak.controller;

import java.security.Principal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
//@RequestMapping("/api")
public class RootController {


    @GetMapping("/open")
    public ResponseEntity<String> sayHello1() {

        return ResponseEntity.ok("Open API Hello after Logout success");
    }


    @GetMapping("/api/hello")
    public ResponseEntity<String> sayHello() {
        DefaultOidcUser user = ((DefaultOidcUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        System.out.println(user.getUserInfo().getClaims().get("preferred_username"));
        return ResponseEntity.ok("Hello");
    }

    @GetMapping("/api/admin")
    public ResponseEntity<String> sayHelloToAdmin(Principal principal) {
        DefaultOidcUser user = ((DefaultOidcUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        System.out.println(user.getUserInfo().getClaims().get("preferred_username"));
        return ResponseEntity.ok("Hello Admin : "+user.getUserInfo().getClaims().get("preferred_username"));
    }

    @GetMapping("/api/user")
    public ResponseEntity<String> sayHelloToUser(Principal principal) {
        return ResponseEntity.ok("Hello User :"+principal.getName());
    }

    @GetMapping("/api/client-secret")
    public ResponseEntity<String> sayHelloToClientSecret(Principal principal){
        return ResponseEntity.ok("Hello User :"+principal.getName());
    }
}
