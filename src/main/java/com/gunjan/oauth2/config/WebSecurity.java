package com.gunjan.oauth2.config;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

import com.gunjan.oauth2.dao.UserDAO;

@Configuration
public class WebSecurity extends WebSecurityConfigurerAdapter
{
    
    @Autowired
    UserDAO userDAO;
    
    public Collection<? extends GrantedAuthority> getAuthorities(String username)
    {
        Map<String,String> roles = new HashMap<>();
        roles.put("admin", "ADMIN");
        roles.put("other", "ADMIN");
        Set<SimpleGrantedAuthority> grantedAuthorities = new HashSet<>();
        for(Map.Entry<String,String> entry : roles.entrySet())
        {
            if(username.equals(entry.getKey())) grantedAuthorities.add(new SimpleGrantedAuthority(entry.getValue()));
            else grantedAuthorities.add(new SimpleGrantedAuthority(entry.getValue()));
        }
        return grantedAuthorities;
        
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception
    {
        
        auth.userDetailsService(userDAO).passwordEncoder(NoOpPasswordEncoder.getInstance());
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDAO);
        daoAuthenticationProvider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
    }
    
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean()
            throws Exception
    {
        return super.authenticationManagerBean();
    }
    
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception
    {
        httpSecurity.authorizeRequests().antMatchers("/").permitAll().and()
                .authorizeRequests().antMatchers("/h2-console/**","/oauth/authorize/**").permitAll().and().formLogin();
        httpSecurity.csrf().disable();
        httpSecurity.headers().frameOptions().disable();
    
}
    
}
