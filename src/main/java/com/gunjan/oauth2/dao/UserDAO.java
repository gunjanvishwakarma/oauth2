package com.gunjan.oauth2.dao;

import com.gunjan.oauth2.repo.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

@Component
public class UserDAO implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {
        Optional<com.gunjan.oauth2.model.User> user = userRepository.findById(username);
        if(user.isPresent()){
            GrantedAuthority authority = new SimpleGrantedAuthority(user.get().getRole());
            UserDetails userDetails = new User(user.get().getUserName(),
                    user.get().getPassword(), Arrays.asList(authority));
            return userDetails;
        }
       
        throw new UsernameNotFoundException(username);
    }
    
    public static void main(String[] args)
    {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(11);
        System.out.println(bCryptPasswordEncoder.encode("novell"));
    }
} 