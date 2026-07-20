package com.pkm.poc.Keycloak.config;

import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authz -> authz
                .requestMatchers("/open", "/error", "/webjars/**", "/unauthenticated",
                        "/oauth2/**", "/login/**").permitAll()
                .requestMatchers("/api/login", "/api/logout").permitAll()
                .anyRequest().authenticated()
        );

        http.sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));

        http.csrf(csrf -> csrf.disable());

        http.oauth2Login(oauth2Login -> oauth2Login
                .authorizationEndpoint(authorization -> authorization
                        .authorizationRequestResolver(
                                authorizationRequestResolver(clientRegistrationRepository)
                        )
                )
                .userInfoEndpoint(userInfo -> userInfo
                        .userAuthoritiesMapper(grantedAuthoritiesMapperRoles())
                )
        );

        http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
        );

        http.logout(logout -> logout
                .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository))
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
        );

        return http.build();
    }

    @Bean
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler(
            ClientRegistrationRepository clientRegistrationRepository) {
        OidcClientInitiatedLogoutSuccessHandler successHandler =
                new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        successHandler.setPostLogoutRedirectUri(
                URI.create("http://localhost:9090/keycloak/open").toString());
        return successHandler;
    }

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {
        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(
                OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<GrantedAuthority> authorities = new java.util.ArrayList<>();

            // Extract realm roles from "realm_access.roles" claim
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null) {
                @SuppressWarnings("unchecked")
                List<String> realmRoles = (List<String>) realmAccess.get("roles");
                if (realmRoles != null) {
                    realmRoles.forEach(role ->
                            authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
                }
            }

            // Extract client roles from "resource_access.{clientId}.roles" claim
            Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
            if (resourceAccess != null) {
                @SuppressWarnings("unchecked")
                Map<String, Object> clientRoles = (Map<String, Object>)
                        resourceAccess.get("spring-boot-authorization-code");
                if (clientRoles != null) {
                    @SuppressWarnings("unchecked")
                    List<String> roles = (List<String>) clientRoles.get("roles");
                    if (roles != null) {
                        roles.forEach(role ->
                                authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
                    }
                }
            }

            return authorities;
        });
        return converter;
    }

    private GrantedAuthoritiesMapper grantedAuthoritiesMapperRoles() {
        return (authorities) -> {
            var mappedAuthorities = new java.util.HashSet<GrantedAuthority>();

            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority userAuthority) {
                    mappedAuthorities.add(new OidcUserAuthority(
                            "OIDC_USER", userAuthority.getIdToken(), userAuthority.getUserInfo()));

                    Map<String, Object> realmAccess = userAuthority.getUserInfo()
                            .getClaimAsMap("realm_access");
                    if (realmAccess != null) {
                        @SuppressWarnings("unchecked")
                        List<String> realmRoles = (List<String>) realmAccess.get("roles");
                        if (realmRoles != null) {
                            realmRoles.forEach(role ->
                                    mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
                        }
                    }

                    Map<String, Object> resourceAccess = userAuthority.getUserInfo()
                            .getClaimAsMap("resource_access");
                    if (resourceAccess != null) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> clientRoles = (Map<String, Object>)
                                resourceAccess.get("spring-boot-authorization-code");
                        if (clientRoles != null) {
                            @SuppressWarnings("unchecked")
                            List<String> roles = (List<String>) clientRoles.get("roles");
                            if (roles != null) {
                                roles.forEach(role ->
                                        mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
                            }
                        }
                    }

                } else if (authority instanceof OAuth2UserAuthority userAuthority) {
                    mappedAuthorities.add(new OAuth2UserAuthority(
                            "OAUTH2_USER", userAuthority.getAttributes()));
                } else {
                    mappedAuthorities.add(authority);
                }
            });

            return mappedAuthorities;
        };
    }
}
