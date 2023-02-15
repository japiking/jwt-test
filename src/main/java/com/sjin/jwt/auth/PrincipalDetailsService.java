package com.sjin.jwt.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.sjin.jwt.model.User;
import com.sjin.jwt.repository.UserRepository;

//http://localhost:8080/login -> 여기서 동작 안함.
@Service
public class PrincipalDetailsService implements UserDetailsService{

	@Autowired
	private UserRepository userRepository;
	
	public PrincipalDetailsService() {
	}

	
	public PrincipalDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("PrincipalDetailsService loadUserByUsername");
		User userEntity = userRepository.findByUsername(username);
		
		return new PrincipalDetails(userEntity);
	}

}
