package com.sjin.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sjin.jwt.model.User;

//CRUD함수를 JpRepository가 들고 있음
//@Repository라는 어노테이션 없어도 loc됨. JapRepository 상속받았기 때문
public interface UserRepository extends JpaRepository<User, Long>{
	
	//findBy규칙 -> username문법 Jpa 쿼리메소드
	//select * from user where username = ? 
	public User findByUsername(String username);//Jpa name 함수
	
	//select * from user where email = ?
//	public User findByEmail();
}
