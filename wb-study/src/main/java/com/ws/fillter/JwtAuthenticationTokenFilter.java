package com.ws.fillter;

import com.ws.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Objects;

@Component
@Order(1)
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {



        //获取token
        String token = request.getHeader("token");
        System.out.println("token=="+token);
        if(token == null){
            System.out.println("未携带 token 首部");
            //放行 进去其他的过滤器
            filterChain.doFilter(request,response);
            //调用会回来的 不可以让他执行下面的 代码哦
            return;
        }
        User user = new User();
        //解析token
        System.out.println("让进");
        //完事从redis中取出来LoginUser 这里要比对的
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken //这个传进去的是从redis中取出来的对象哦
                = new UsernamePasswordAuthenticationToken(
                user
                ,null, null);
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        //放行
        filterChain.doFilter(request,response);
    }
}
