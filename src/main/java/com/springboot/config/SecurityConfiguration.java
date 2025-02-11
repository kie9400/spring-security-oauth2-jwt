package com.springboot.config;

import com.springboot.auth.filter.JwtAuthenticationFilter;
import com.springboot.auth.filter.JwtVerificationFilter;
import com.springboot.auth.handler.AuthenticationFailureHandler;
import com.springboot.auth.handler.AuthenticationSuccessHandler;
import com.springboot.auth.handler.MemberAccessDeniedHandler;
import com.springboot.auth.handler.MemberAuthenticationEntryPoint;
import com.springboot.auth.jwt.JwtTokenizer;
import com.springboot.auth.utils.AuthorityUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class SecurityConfiguration {
    //JwtAuthenticationFilter에서 사용되기에 DI
    private final JwtTokenizer jwtTokenizer;
    private final AuthorityUtils authorityUtils;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer, AuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //시큐리티 설정을 통해 인증, 인가를 설정할 수 있음
        http
                //H2 웹 콘솔을 사용하기 위해 추가
                .headers().frameOptions().sameOrigin()
                .and()
                //csrf공격 보안설정 비활성화 (설정하지 않으면 403에러)
                //JWT 방식에서는 세션을 사용하지 않기 때문에 CSRF 공격에 대한 보호가 필요하지 않아 비활성화
                .csrf().disable()
                //CorsConfigurationSource Bean을 제공하여 CorsFilter를 적용함으로써 CORS를 처리
                .cors(Customizer.withDefaults())
                //JWT는 클라이언트 정보 등의 상태를 저장하지 않는 Stateless한 방식
                //SecurityContext에 Authenticaiton를 저장하면 세션 정책에 의해 세션을 생성할 가능성이 있음
                //JWT 환경에서는 세션 정책 설정을 통해 세션 자체를 생성하지 않도록 설정해야 한다.
                //stateless한 애플리케이션을 유지하기 위해 세션을 생성하지 않도록 설정
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                //폼 로그인과 http basic 인증방식 비활성화
                .formLogin().disable()
                .httpBasic().disable()
                //예외를 처리할 로직을 시큐리티에 등록(예외 핸들링)
                .exceptionHandling()
                //인증 예외
                .authenticationEntryPoint(new MemberAuthenticationEntryPoint())
                //인가 예외
                .accessDeniedHandler(new MemberAccessDeniedHandler())
                .and()
                //커스터마이징된 Configuration을 추가
                .apply(new CustomFilterConfigurer())
                .and()
                //서버측으로 들어오는 request의 접근 권한 설정
                .authorizeHttpRequests(authorize -> authorize
                        //HTTP Method가 POST에 해당되면 회원등록에 해당되는 URL은 모두 접근을 허용
                        //MemberController의 postMember() 핸들러 메서드에 대한 접근권한 부여 설정
                        .antMatchers(HttpMethod.POST, "/*/members").permitAll()
                        //PATCH는 USER권한을 가진 사용자만 접근가능
                        // "/**"는 하위 URL로 어떤 URL이 들어오더라도 매치가 된다는 의미
                        .antMatchers(HttpMethod.PATCH, "/*/members/**").hasRole("USER")
                        //전체 회원 조회(GET)는 ADMIN 권한을 가진 사용자만 접근가능
                        .antMatchers(HttpMethod.GET, "/*/members").hasRole("ADMIN")
                        .antMatchers(HttpMethod.GET, "/*/members/**").hasAnyRole("USER", "ADMIN")
                        .antMatchers(HttpMethod.DELETE, "/*/members/**").hasRole("USER")

                        //커피 접근 권한 설정
                        .antMatchers(HttpMethod.POST, "/*/coffees").hasRole("ADMIN")
                        //조회는 비회원이여도 되어야한다. ( 없어도 작동은 되지만 코드의 명확성이 좋아지니까 넣자 )
                        .antMatchers(HttpMethod.GET,"/*/coffees").permitAll()
                        .antMatchers(HttpMethod.GET,"/*/coffees/**").permitAll()
                        .antMatchers(HttpMethod.PATCH, "/*/coffees/**").hasRole("ADMIN")
                        .antMatchers(HttpMethod.DELETE, "/*/coffees/**").hasRole("ADMIN")

                        //주문 접근권한 설정
                        .antMatchers(HttpMethod.POST,"/*/orders").hasAnyRole("USER", "ADMIN")
                        .antMatchers(HttpMethod.PATCH,"/*/orders/**").hasAnyRole("USER", "ADMIN")
                        .antMatchers(HttpMethod.GET,"/*/orders").hasRole("ADMIN")
                        .antMatchers(HttpMethod.GET,"/*/orders/**").hasAnyRole("USER", "ADMIN")
                        .antMatchers(HttpMethod.DELETE,"/*/orders/**").hasAnyRole("USER", "ADMIN")
                        //위에 설정한 요청 이외에 모든 요청의 접근은 허용한다.
                        .anyRequest().permitAll());
        return http.build();
    }

    //passwordEncoder Bean 객체 생성
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //CORS 기본설정
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        //모든 출처에 대해 스크립트 기반의 HTTP 통신을 허용
        configuration.setAllowedOrigins(Arrays.asList("*"));
        //파라미터로 지정한 HTTP Method에 대한 통신을 허용
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PATCH", "DELETE"));

        // CorsConfigurationSource 인터페이스의 구현체 UrlBasedCorsConfigurationSource 객체를 생성
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        //모든 URL에 지금까지 구성한 CORS 정책을 적용한다.
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    //Custom Configurer : Spring Security의 Configuratuon를 개발자가 정의한 클래스
    //JwtAuthenticationFilter를 등록하는 역할
    //AbstractHttpConfigurer<AbstractHttpConfigurer를 상속하는 타입, HttpSecurityBuilder를 상속하는 타입>
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity>{
        //Configuration 커스터마이징
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            //AuthenticationManager 객체를 생성
            //getSharedObject 메서드를 통해 Spring Security의 설정을 구성하는 SecurityConfigurer간에 공유되는 객체를 얻을 수 있다.
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

            //JwtAuthenticationFilter를 생성하면서 필요한 인자를 Di해준다.
            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);  // (2-4)

            //디폴트 request URL를 /login -> /v11/auth/login으로 변경
            jwtAuthenticationFilter.setFilterProcessesUrl("/v11/auth/login");

            //(인증 필터에서만 사용)인증 성공/실패 시 한 번만 동작하는 코드들이기 때문에 굳이 Bean으로 등록하지 않아도된다.
            jwtAuthenticationFilter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler());
            jwtAuthenticationFilter.setAuthenticationFailureHandler(new AuthenticationFailureHandler());

            //JWT검증필터 클래스의 인스턴스를 생성하면서 필요한 객체를 DI
            JwtVerificationFilter jwtVerificationFilter = new JwtVerificationFilter(jwtTokenizer, authorityUtils);

            //JwtAuthenticationFilter를 Spring Security Filter Chain에 추가한다.
            builder
                    .addFilter(jwtAuthenticationFilter)
                    //무조건 검증필터는 인증필터에서 인증이 성공한 후
                    //발급받은 JWT가 클라의 request header에 포함되어있을 경우에 동작
                    //그렇기에 addFilterAfter(검증필터, 인증필터)를 사용
                    .addFilterAfter(jwtVerificationFilter, JwtAuthenticationFilter.class);
        }
    }
}