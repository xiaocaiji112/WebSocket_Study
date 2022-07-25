package com.ws.fillter;


import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Order(2)
public class FIllterT  extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("request.getRequestURI() = " + request.getRequestURI());
        String token = request.getParameter("token");
        if(token != null){
            System.out.println("执行");
            filterChain.doFilter(request,response);
        }else {
            System.out.println("不执行");
            filterChain.doFilter(request,response);
        }

    }
}
