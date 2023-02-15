package com.sjin.jwt.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.sjin.jwt.model.User;
import com.sjin.jwt.repository.UserRepository;

@RestController
public class RestApiController {
	
	public RestApiController() {
		
	}
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private BCryptPasswordEncoder  bCryptPasswordEncoder;
	
	@GetMapping("/home")
	public String home() {
		return "<h1>home</h1>";
	}
	
	@PostMapping("/token")
	public String token() {
		return "<h1>token</h1>";
	}
	
	@GetMapping("/admin/users")
	public List<User> users(){
		return userRepository.findAll();
	}
	
	@PostMapping("/join")
	public String join(@RequestBody User user) {
		System.out.println("==================================");
		System.out.println(user);
		user.setRoles("ROLE_USER");
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encPassword);
		
		userRepository.save(user);//회원강비 잘됨, 비밀번호 1234 -> 시큐리티로 로그인 할 수 없음. 이유는 패스워드가 암호화가 안되었기 때문
		return "회원가입완료";
	}
	
	//user, manager, admin
	@GetMapping("/api/v1/admin")
	public String admin() {
		return "admin";
	}
	
	//user, manager 접근가능
	@GetMapping("/api/v1/manager")
	public String manager() {
		return "manager";
	}
	//user권하만 접근 가능
	@GetMapping("/api/v1/user")
	public String user() {
		return "user";
	}
}
