package com.gunjan.oauth2.model;

import javax.annotation.Generated;
import javax.persistence.Entity;
import javax.persistence.Id;

import org.hibernate.id.Assigned;

@Entity
public class User
{
    @Id
    private String userName;
    private String password;
    private String role;
    
    public String getUserName()
    {
        return userName;
    }
    
    public void setUserName(String userName)
    {
        this.userName = userName;
    }
    
    public String getPassword()
    {
        return password;
    }
    
    public void setPassword(String password)
    {
        this.password = password;
    }
    
    public String getRole()
    {
        return role;
    }
    
    public void setRole(String role)
    {
        this.role = role;
    }
}
