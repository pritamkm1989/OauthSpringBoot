package com.pkm.poc.Keycloak.config;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Autowired
    private  ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authz) ->
                authz.requestMatchers("/open","/error", "/webjars/**", "/unauthenticated", "/oauth2/**", "/login/**").permitAll().
                        anyRequest().fullyAuthenticated());

        http.sessionManagement(sess -> sess.sessionCreationPolicy(
                SessionCreationPolicy.ALWAYS));

        http
                .oauth2Login((oauth2Login) -> oauth2Login
                        .userInfoEndpoint((userInfo) -> userInfo
                                .userAuthoritiesMapper(grantedAuthoritiesMapper())
                        )
                ).logout((logout) -> logout
                        .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository))

                );


        return http.build();

    }

    @Bean
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        successHandler.setPostLogoutRedirectUri(URI.create("http://localhost:9090/keycloak/open").toString());
        return successHandler;
    }




    private GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach((authority) -> {
                GrantedAuthority mappedAuthority;

                if (authority instanceof OidcUserAuthority) {
                    OidcUserAuthority userAuthority = (OidcUserAuthority) authority;
                    mappedAuthority = new OidcUserAuthority(
                            "OIDC_USER", userAuthority.getIdToken(), userAuthority.getUserInfo());
                } else if (authority instanceof OAuth2UserAuthority) {
                    OAuth2UserAuthority userAuthority = (OAuth2UserAuthority) authority;
                    mappedAuthority = new OAuth2UserAuthority(
                            "OAUTH2_USER", userAuthority.getAttributes());
                } else {
                    mappedAuthority = authority;
                }

                mappedAuthorities.add(mappedAuthority);
            });

            return mappedAuthorities;
        };
    }

    /*@Bean
    public ClientRegistrationRepository clientRepository() {

        ClientRegistration keycloak = keycloakClientRegistration();
        return new InMemoryClientRegistrationRepository(keycloak);
    }

    private ClientRegistration keycloakClientRegistration() {

        return ClientRegistration.withRegistrationId("spring-boot-test")
                .clientId("spring-boot-authorization-code")
                .clientSecret("6cwXqAuhWR9zWHOO86ssO8NQxlD0NVrn")
                //.redirectUri("http://localhost:9090/keycloak/api/admin")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .issuerUri("http://localhost:8080/realms/spring-boot-test")
                .authorizationUri("http://localhost:8080/realms/spring-boot-test/protocol/openid-connect/auth")
                .tokenUri("http://localhost:8080/realms/spring-boot-test/protocol/openid-connect/token")
                .userInfoUri("http://localhost:8080/realms/spring-boot-test/protocol/openid-connect/userinfo")
                .build();
    }*/
}
