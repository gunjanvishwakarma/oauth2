package com.gunjan.oauth2.config;

import com.gunjan.oauth2.constants.GrantType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter {


    @Value("${zenoauth2.client_credentials_grant.clientId}")
    private String client_credentials_clientId;

    @Value("${zenoauth2.client_credentials_grant.clientSecret}")
    private String client_credentials_clientSecret;

    @Value("${zenoauth2.client_credentials_grant.scope}")
    private String client_credentials_scope;

    @Value("${zenoauth2.client_credentials_grant.authorities}")
    private String client_credentials_authorities;

    @Value("${zenoauth2.password_grant.clientId}")
    private String password_grant_clientId;

    @Value("${zenoauth2.password_grant.clientSecret}")
    private String password_grant_clientSecret;

    @Value("${zenoauth2.password_grant.scope}")
    private String password_grant_scope;

    @Value("${zenoauth2.password_grant.accessTokenValiditySeconds}")
    private Integer password_grant_accessTokenValiditySeconds;

    @Value("${zenoauth2.password_grant.refreshTokenValiditySeconds}")
    private Integer password_grant_refreshTokenValiditySeconds;

    @Value("${zenoauth2.authorization_code_grant.clientId}")
    private String authorization_code_grant_clientId;

    @Value("${zenoauth2.authorization_code_grant.clientSecret}")
    private String authorization_code_grant_clientSecret;

    @Value("${zenoauth2.authorization_code_grant.scope}")
    private String authorization_code_grant_scope;

    @Value("${zenoauth2.authorization_code_grant.redirectUris}")
    private String authorization_code_redirectUris;

    @Value("${zenoauth2.keystore.name}")
    private String keystore;

    @Value("${zenoauth2.keystore.pass}")
    private String keystorepass;

    @Value("${zenoauth2.key.name}")
    private String key;

    @Value("${zenoauth2.key.pass}")
    private String keypass;
    
    @Value("${zenoauth2.implicit_grant.clientId}")
    private String implicit_grant_clientId;
    
    @Value("${zenoauth2.implicit_grant.scope}")
    private String implicit_grant_scope;

    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory().
                withClient(client_credentials_clientId).
                secret(client_credentials_clientSecret).
                authorizedGrantTypes(GrantType.CLIENT_CREDENTIALS.getGrantType()).
                scopes(client_credentials_scope.split(",")).
                authorities(client_credentials_authorities.split(",")).
                and().
                withClient(password_grant_clientId).
                secret(password_grant_clientSecret).
                accessTokenValiditySeconds(password_grant_accessTokenValiditySeconds).
                refreshTokenValiditySeconds(password_grant_refreshTokenValiditySeconds).
                authorizedGrantTypes(GrantType.REFRESH_TOKEN.getGrantType(), GrantType.PASSWORD.getGrantType()).
                scopes(password_grant_scope.split(",")).
                and().
                withClient(authorization_code_grant_clientId).
                secret(authorization_code_grant_clientSecret).
                authorizedGrantTypes(GrantType.AUTHORIZATION_CODE.getGrantType()).
                scopes(authorization_code_grant_scope.split(",")).
                redirectUris(authorization_code_redirectUris.split(",")).
                and().
                withClient(implicit_grant_clientId)
                .secret(implicit_grant_clientId)
                .authorizedGrantTypes(GrantType.IMPLICIT.getGrantType())
                .scopes(implicit_grant_scope.split(","))
                .redirectUris(authorization_code_redirectUris.split(","))
                .autoApprove(true);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                .accessTokenConverter(jwtAccessTokenConverter())
                .tokenServices(defaultTokenServices());
    }

    @Bean
    public DefaultTokenServices defaultTokenServices() {
        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setTokenEnhancer(tokenEnhancerChain());
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }

    @Bean
    public JwtTokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        KeyPair keyPair = new KeyStoreKeyFactory(
                new ClassPathResource(keystore), keystorepass.toCharArray())
                .getKeyPair(key, keypass.toCharArray());
        converter.setKeyPair(keyPair);
        return converter;
    }

    @Bean
    public TokenEnhancerChain tokenEnhancerChain() {
        final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(jwtAccessTokenConverter()));
        return tokenEnhancerChain;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security.passwordEncoder(new BCryptPasswordEncoder(11))
                .checkTokenAccess("permitAll()")
                .tokenKeyAccess("permitAll()");
    }
}
