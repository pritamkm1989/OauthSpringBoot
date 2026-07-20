package com.pkm.poc.Keycloak.controller;

import com.pkm.poc.Keycloak.dto.LoginRequest;
import com.pkm.poc.Keycloak.dto.LoginResponse;
import com.pkm.poc.Keycloak.service.KeycloakTokenService;
import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class RootController {

    private final KeycloakTokenService keycloakTokenService;

    public RootController(KeycloakTokenService keycloakTokenService) {
        this.keycloakTokenService = keycloakTokenService;
    }

    @GetMapping("/open")
    public ResponseEntity<String> sayHello1() {
        return ResponseEntity.ok("Open API Hello after Logout success");
    }

    @PostMapping("/api/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        Map<String, Object> tokenResponse = keycloakTokenService.login(
                request.getUsername(), request.getPassword());

        return ResponseEntity.ok(new LoginResponse(
                (String) tokenResponse.get("access_token"),
                (String) tokenResponse.get("refresh_token"),
                ((Number) tokenResponse.get("expires_in")).intValue(),
                (String) tokenResponse.get("token_type")
        ));
    }

    @PostMapping("/api/logout")
    public ResponseEntity<String> logout(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refresh_token");
        if (refreshToken != null) {
            keycloakTokenService.logout(refreshToken);
        }
        return ResponseEntity.ok("Logged out successfully");
    }

    @GetMapping("/api/hello")
    public ResponseEntity<Map<String, Object>> sayHello(Principal principal) {
        Map<String, Object> claims = getClaims(principal);
        return ResponseEntity.ok(Map.of(
                "message", "Hello",
                "user", claims.getOrDefault("preferred_username", "unknown"),
                "realm_roles", getRealmRoles(claims),
                "flow", principal instanceof OidcUser ? "OIDC (Browser/PKCE)" : "JWT (API Login)"
        ));
    }

    @GetMapping("/api/admin")
    @PreAuthorize("hasRole('spring-boot-admin')")
    public ResponseEntity<Map<String, Object>> sayHelloToAdmin(Principal principal) {
        Map<String, Object> claims = getClaims(principal);
        log.info("Admin access by: {}", claims.get("preferred_username"));
        return ResponseEntity.ok(Map.of(
                "message", "Hello Admin",
                "user", claims.getOrDefault("preferred_username", "unknown"),
                "realm_roles", getRealmRoles(claims),
                "flow", principal instanceof OidcUser ? "OIDC (Browser/PKCE)" : "JWT (API Login)"
        ));
    }

    @GetMapping("/api/user")
    @PreAuthorize("hasRole('spring-boot-user')")
    public ResponseEntity<Map<String, Object>> sayHelloToUser(Principal principal) {
        Map<String, Object> claims = getClaims(principal);
        log.info("User access by: {}", claims.get("preferred_username"));
        return ResponseEntity.ok(Map.of(
                "message", "Hello User",
                "user", claims.getOrDefault("preferred_username", "unknown"),
                "realm_roles", getRealmRoles(claims),
                "flow", principal instanceof OidcUser ? "OIDC (Browser/PKCE)" : "JWT (API Login)"
        ));
    }

    @GetMapping("/api/client-secret")
    public ResponseEntity<Map<String, Object>> sayHelloToClientSecret(Principal principal) {
        Map<String, Object> claims = getClaims(principal);
        return ResponseEntity.ok(Map.of(
                "message", "Hello",
                "user", claims.getOrDefault("preferred_username", "unknown"),
                "flow", principal instanceof OidcUser ? "OIDC (Browser/PKCE)" : "JWT (API Login)"
        ));
    }

    @GetMapping("/api/me")
    public ResponseEntity<Map<String, Object>> me(Principal principal) {
        Map<String, Object> claims = getClaims(principal);
        return ResponseEntity.ok(Map.of(
                "sub", claims.getOrDefault("sub", "unknown"),
                "preferred_username", claims.getOrDefault("preferred_username", "unknown"),
                "email", claims.getOrDefault("email", "unknown"),
                "realm_roles", getRealmRoles(claims),
                "client_roles", getClientRoles(claims),
                "flow", principal instanceof OidcUser ? "OIDC (Browser/PKCE)" : "JWT (API Login)"
        ));
    }

    private Map<String, Object> getClaims(Principal principal) {
        if (principal instanceof Jwt jwt) {
            return jwt.getClaims();
        } else if (principal instanceof OidcUser oidcUser) {
            return oidcUser.getClaims();
        } else if (principal instanceof JwtAuthenticationToken  tokenAuthenticationToken) {
            return tokenAuthenticationToken.getTokenAttributes();
        }
        else if (principal instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken) {
            return oAuth2AuthenticationToken.getPrincipal().getAttributes();
        }


        return Collections.emptyMap();
    }

    @SuppressWarnings("unchecked")
    private List<String> getRealmRoles(Map<String, Object> claims) {
        Object realmAccess = claims.get("realm_access");
        if (realmAccess instanceof Map<?, ?> realmMap) {
            Object roles = realmMap.get("roles");
            if (roles instanceof List<?> roleList) {
                return roleList.stream()
                        .map(String.class::cast)
                        .toList();
            }
        }
        return Collections.emptyList();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getClientRoles(Map<String, Object> claims) {
        Object resourceAccess = claims.get("resource_access");
        if (resourceAccess instanceof Map<?, ?> resourceMap) {
            Object clientRoles = resourceMap.get("spring-boot-authorization-code");
            if (clientRoles instanceof Map<?, ?> rolesMap) {
                return (Map<String, Object>) rolesMap;
            }
        }
        return Collections.emptyMap();
    }
}
