package com.ws.config;

import com.ws.fillter.FIllterT;
import com.ws.fillter.JwtAuthenticationTokenFilter;

import com.ws.handl.AuthenticationEntryPointImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    JwtAuthenticationTokenFilter authenticationTokenFilter;
    @Autowired
    FIllterT fIllterT;
    @Bean
    public PasswordEncoder passwordEncoder (){
        return  new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Autowired
    AuthenticationEntryPointImpl authenticationEntryPoint;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //关闭csrf
                .csrf().disable().
                //不通过Session获取SecurityContext
                        sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                // 对于登录接口允许匿名访问
                .antMatchers("/user/login","/javatest/ws/**","/websocket/test").anonymous()

                //出上面以外的所有请求全部需要鉴全认证
                .anyRequest().authenticated();
        //添加过滤器
         http.addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
         http.addFilterBefore(fIllterT,UsernamePasswordAuthenticationFilter.class);

        http.exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint);

    }
    @Override
    public void configure(WebSecurity web) throws Exception {
/*        web.ignoring().antMatchers(
                "/javatest/ws/**"
        );*/
    }
}
