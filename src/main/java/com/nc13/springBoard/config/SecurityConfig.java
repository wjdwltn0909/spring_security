package com.nc13.springBoard.config;

import com.nc13.springBoard.service.UserAuthService;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, UserAuthService userAuthService) throws Exception {
        httpSecurity
                //Cross Site Request Forgery(CSRF) 방지
                .csrf(AbstractHttpConfigurer::disable)
                // URL 별 권한 설정
                .authorizeHttpRequests((authorize) -> authorize
                        // localhost:8080/user/... 이거나 localhost:8080/ 은 누구든 접근 가능
                        .requestMatchers("/user/*").permitAll()
                        // /board/..../...,  /reply/.. /...은 로그인한 사용자만 접근 가능
                        .anyRequest().authenticated()

        )
                // 커스텀 폼 로그인 설정;
                .formLogin((formLogIn) -> formLogIn
                        // 로그인에서 사용할 페이지 설정
                        .loginPage("/")
                        // 로그인 페이지에서 username을 "어떤  name 어트리뷰트"로 넘겨줄지 설정
                        .usernameParameter("username")
                        // 로그인 페이지에서 password를 "어떤  name 어트리뷰트"로 넘겨줄지 설정
                        .passwordParameter("password")
                        // 로그인 성공 시 이동할 페이지
                        .defaultSuccessUrl("/board/showAll/1")
                        // 로그인 처리 URL
                        .loginProcessingUrl("/user/auth"))

                // 내가 만든 userAuth Service등록
                .userDetailsService(userAuthService);



        return httpSecurity.build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

