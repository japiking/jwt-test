package com.sjin.jwt;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sjin.jwt.auth.PrincipalDetails;
import com.sjin.jwt.model.User;
import com.sjin.jwt.repository.UserRepository;

// 시큐리티가 filter가지고 있는데 그 필터주엥 BasicAuthenticationFilter라는것이 있음.
// 권한이나 인증이 필요한 특정 주소를 요청했을대 위 필터를 무조건 타게 되어 있음.
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안탐.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{
	
	private UserRepository userRepository;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}
	
	//인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 될것
	@Override
	protected void doFilterInternal(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, javax.servlet.FilterChain chain) throws java.io.IOException ,javax.servlet.ServletException {
		System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");
		
		String jwtHeader = request.getHeader("Authorization");
		System.out.println("jwtHeader:"+ jwtHeader);
		
		//header가 있는지 확인
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		System.out.println("No process");
		
		//JWT토큰을 검증을 해서 정상적인 사용자인지 확인
		String jwtToken = request.getHeader("Authorization").replace("Beaer ", "").replaceAll("\n", "");
				
		String username = 
				JWT.require(Algorithm.HMAC512("SJIN")).build().verify(jwtToken).getClaim("username").asString();
		
		//서명이 정샂적으로 됨
		if(username != null) {
			User userEntity = userRepository.findByUsername(username);

			PrincipalDetails principaDetails = new PrincipalDetails(userEntity);
			
			//JWT토큰 서명을 통해서 서명이 정상이면 Authenticatio 객체를 만들어준다.
			Authentication authentication = 
					new UsernamePasswordAuthenticationToken(principaDetails, null, principaDetails.getAuthorities());
			
			//강제로 시큐리티의 세션에 접근하여 Authentication 에 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			chain.doFilter(request, response);
		}
		
				
	};

}
