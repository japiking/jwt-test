package com.sjin.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//토큰:cos 이걸 만들어줘야 함. id, pwd정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답ㅇ르 해준다.
		//요청할 때 마다 header에 Authorization에 value값으로 토큰을 가지고 오겠죠?
		//그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 됨(RSA, HS256)
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		req.setCharacterEncoding("UTF-8");
		
//		if(req.getMethod().equals("POST")) {
//			System.out.println("POST request");
//			String headerAuth = req.getHeader("Authorization");
//			System.out.println("headerAuth : " + headerAuth);
//			
//			if(headerAuth.equals("cos")){
//				chain.doFilter(req, res);
//			}else { 
//				PrintWriter out = res.getWriter();
//				out.println("No Auth");
//			}
//		}
		chain.doFilter(req, res);
		System.out.println("Filter3");
		
	}

}
