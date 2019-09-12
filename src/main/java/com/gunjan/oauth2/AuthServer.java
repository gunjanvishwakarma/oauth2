package com.gunjan.oauth2;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class AuthServer
{
    
    public static void main(String[] args)
    {
        new SpringApplicationBuilder(AuthServer.class).run(args);
        
    }
}
