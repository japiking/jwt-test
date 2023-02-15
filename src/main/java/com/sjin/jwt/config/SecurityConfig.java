package com.sjin.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

import com.sjin.jwt.JwtAuthorizationFilter;
import com.sjin.jwt.config.jwt.JwtAuthenticationFilter;
import com.sjin.jwt.filter.MyFilter3;
import com.sjin.jwt.repository.UserRepository;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Autowired
	private CorsFilter corsFilter;
	
	@Autowired
	private UserRepository userRepository;
	
	//해당 메소드의 리턴되는 오브젝트를 loc로 등록
	@Bean
	BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		AuthenticationManager authenticationManager = authenticationManager(http.getSharedObject(AuthenticationConfiguration.class));
		
		//http.addFilterAfter(new MyFilter3(), BasicAuthenticationFilter.class);
		http.addFilterAfter(new MyFilter3(), UsernamePasswordAuthenticationFilter.class);
		
		http.csrf().disable();			//토큰체크 비활성화
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//세션 미사용
		.and()
		.addFilter(corsFilter)//@CrossOrigin(인증x), 시큐리티 필터에 등록 인증(o)
		.formLogin().disable()//form로그인 미사용
		.httpBasic().disable()//id/pwd를 authorization 에 담아 요청하는 방식 미사용
		.addFilter(new JwtAuthenticationFilter(authenticationManager))// AuthoenticationManager formlogin사용하지 않기 때문에 필터로 추가
		.addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository)) // AuthoenticationManager formlogin사용하지 않기 때문에 필터로 추가
		.authorizeRequests()  // 요청에 의한 보안검사 시작
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") //접근시 롤체크
		.antMatchers("/api/v1/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") //접근시 롤체크
		.antMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN') ")
		.anyRequest().permitAll();  
		
		
		return http.build();
	}
	
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
