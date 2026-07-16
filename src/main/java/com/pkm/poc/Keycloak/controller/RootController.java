package com.pkm.poc.Keycloak.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
//@RequestMapping("/api")
@Slf4j
public class RootController {


    @GetMapping("/open")
    public ResponseEntity<String> sayHello1() {

        return ResponseEntity.ok("Open API Hello after Logout success");
    }


    @GetMapping("/api/hello")
    public ResponseEntity<String> sayHello() {
        DefaultOidcUser user = ((DefaultOidcUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        System.out.println(user.getUserInfo().getClaims().get("preferred_username"));
        return ResponseEntity.ok("Hello"+user.getUserInfo().getClaims().get("preferred_username"));
    }

    @GetMapping("/api/admin")
    @PreAuthorize("hasRole('spring-boot-admin')")
    public ResponseEntity<String> sayHelloToAdmin(Principal principal) {
        DefaultOidcUser user = ((DefaultOidcUser) ((OAuth2AuthenticationToken) principal).getPrincipal());
        log.info("Cliams {}",user.getUserInfo().getClaims());
        return ResponseEntity.ok("Hello Admin : "+user.getUserInfo().getClaims().get("preferred_username"));
    }

    @GetMapping("/api/user")
    @PreAuthorize("hasRole('spring-boot-user')")
    public ResponseEntity<String> sayHelloToUser(Principal principal) {
        DefaultOidcUser user = ((DefaultOidcUser) ((OAuth2AuthenticationToken) principal).getPrincipal());
        //DefaultOidcUser user = ((DefaultOidcUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        log.info("Cliams {}",user.getUserInfo().getClaims());
        return ResponseEntity.ok("Hello User :"+user.getUserInfo().getClaims().get("preferred_username"));
    }

    @GetMapping("/api/client-secret")
    public ResponseEntity<String> sayHelloToClientSecret(Principal principal){
        return ResponseEntity.ok("Hello User :"+principal.getName());
    }

}
