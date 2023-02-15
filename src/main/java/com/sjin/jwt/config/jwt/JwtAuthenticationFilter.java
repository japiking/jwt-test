package com.sjin.jwt.config.jwt;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjin.jwt.auth.PrincipalDetails;
import com.sjin.jwt.model.User;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리테이서 UsernamePasswordAuthenticationFilter가 있음.
// /login 요청해서 username, password 전송하면(post)
// UsernamePasswordAuthenticationFilter가 동작함.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	// /login요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : Login try");
		//1. username, password 받아서
		try {
			/*
			BufferedReader br = request.getReader();
			String input = null;
			while((input = br.readLine()) != null){
				System.out.println(input);
				
			}
			*/
			ObjectMapper om = new ObjectMapper(); 
			User user = om.readValue(request.getInputStream(),User.class);
			System.out.println(user);
			
			UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			//PrincipalDeailsService의 loaduserByUsername()함수가 실행됨.
			//DB에 있는 username과 password가 일치한다.
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken);
			
			// authentication 객체가 session영역에 저장됨 => 로그인이되었다는 뜻.
			PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
			System.out.println("로그인 완료됨 : "+principalDetails.getUser().getUsername());//로그인 정상적으로 되었다는 뜻.
			//authentication 객체가 session영역에 저장을 해야하고 그방법이 return해주면 됨.
			//리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임.
			// 굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리때문에 session넣어줍니다.
			
			System.out.println("=======================================");
			return authentication;
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("=======================================");
		
		//2. 정상인지 로그인 시도를 해보는 거에요. authenticationManager로 로그인 시도를 하면!!
		//PrincipalDetailsService가 호출 loadUserByUsername() 함수 실행됨.
		
		//3. PrincipalDetails를 세션에 담고(권한 관리를 위해서)
		
		//4. JWT토큰을 만들어서 응답해주면 됨.
		
		return null;
		
	}

	public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}
	
	//atemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication함수가 실행됨.
	//JWT토큰을 만들어서 request 요청한 사용자에게 JWT토큰을 response하면 됨.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();
		
		//RSA방식은 아니고 Hash암호방식
		String jwtToken = JWT.create()
				.withSubject("sjin Token")
				.withExpiresAt(new Date(System.currentTimeMillis()+(1000*60)*10 ))
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512("SJIN"));
		
		response.addHeader("Authorization", "Bearer "+jwtToken);
		
		System.out.println("successfulAuthentication complete!!");
//		super.successfulAuthentication(request, response, chain, authResult);
	}
}
