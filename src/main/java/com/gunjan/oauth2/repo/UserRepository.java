package com.gunjan.oauth2.repo;

import com.gunjan.oauth2.model.User;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User,String>
{

}