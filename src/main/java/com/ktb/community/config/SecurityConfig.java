package com.ktb.community.config;

import com.ktb.community.oauth.handler.CustomOAuth2SuccessHandler;
import com.ktb.community.oauth.service.CustomOAuth2UserService;
import com.ktb.community.repository.RefreshRepository;
import com.ktb.community.util.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Value("${spring.route.front}")
    String front;


    // AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                          CustomOAuth2UserService customOAuth2UserService,
                                          CustomOAuth2SuccessHandler customOAuth2SuccessHandler) throws Exception {

        // CORS 설정 추가
        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();
                        configuration.setAllowedOrigins(Arrays.asList(front,"http://localhost:8080", "http://127.0.0.1:8080"));
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);

                        // 응답 헤더에 access 토큰을 노출하도록 설정
                        configuration.setExposedHeaders(Collections.singletonList("access"));

                        return configuration;
                    }
                }));
        // csrf disable
        http
                .csrf((auth)-> auth.disable());

        // form 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        // http basic 인증 방식 disable
        http
                .httpBasic((auth)-> auth.disable());

        // oauth 로그인
        http
                .oauth2Login((oauth2) -> oauth2
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(customOAuth2UserService))
                        .successHandler(customOAuth2SuccessHandler));

        // 경로별 인가 작업
        http
                .authorizeHttpRequests((auth)-> auth
                        .requestMatchers("/v1/auth/login", "/v1/auth/join", "/v1/auth/reissue", "/oauth2/**", "/v1/chat/connect/**",
                                "/swagger-ui/**", "/v3/api-docs/**", "/v1/terms", "/v1/privacy","/v1/users/me/nickname", "/v1/healthz").permitAll()
                        .requestMatchers("/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated());


        // LoginFilter 추가
        // AuthenticationManager를 가져와서 LoginFilter의 생성자에 주입
        // dto로 받는 로그인 필터를 기존의 UsernamePasswordAuthenticationFilter 자리에 넣음
        AuthenticationManager authenticationManager = authenticationManager(authenticationConfiguration);
        LoginFilter loginFilter = new LoginFilter(authenticationManager, jwtUtil, refreshRepository);
        http
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class);

        // jwt 필터 등록
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // 로그아웃 필터 등록
        http
                .addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshRepository), LoginFilter.class);

        // 세션 설정
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

}
