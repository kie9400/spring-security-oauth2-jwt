package com.springboot.oauth2_jwt.filter;

import com.springboot.oauth2_jwt.jwt.JwtTokenizer;
import com.springboot.oauth2_jwt.utils.JwtAuthorityUtils;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;

//OAtuh2 인증에 성공하면 프론트엔드 애플리케이션 쪽으로 request를 전송하는데
//전송할 때 마다 Authorization header에 실어 보내는 Access token에 대한 검증을 수행하는 필터
//request 1회당 1번만 실행하기에 OncePreRequestFilter를 상속
public class JwtVerificationFilter extends OncePerRequestFilter {
    private final JwtTokenizer jwtTokenizer;
    private final JwtAuthorityUtils authorityUtils;

    public JwtVerificationFilter(JwtTokenizer jwtTokenizer, JwtAuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try{
            Map<String, Object> claims = verifyJws(request);
            setAuthenticationToContext(claims);
        }catch (SignatureException se){
            request.setAttribute("exception", se);
        }catch (ExpiredJwtException ee){
            request.setAttribute("exception", ee);
        }catch (Exception e){
            request.setAttribute("exception", e);

            filterChain.doFilter(request, response);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request)throws ServletException{
        String authorization = request.getHeader("Authorization");
        return authorization == null || !authorization.startsWith("Bearer");
    }

    //JWT를 검증하는 메서드
    private Map<String, Object> verifyJws(HttpServletRequest request){
        //request의 header에서 JWT를 가져온다.
        //클라이언트가 reqeust header로 전송한 JWT를 가져오는것이다.
        //문자열에서 replace() 메서드를 이용해 "Bearer "를 제거
        String jws = request.getHeader("Authorization").replace("Bearer ", "");

        //JWT 서명을 검증하기 위한 Secret Key를 인코딩된 상태로 얻어온다.
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        //JWT 토큰에서 Claims(페이로드에 담긴 정보)를 파싱(추출)한다.
        //파싱이 완료되었다는 것은 내부적으로 시그니처 검증이 성공했다는 뜻
        Map<String, Object> claims = jwtTokenizer.getClaims(jws, base64EncodedSecretKey).getBody();
        return claims;
    }

    //Authentication 객체를 SecurityContext에 저장하기 위한 메서드
    private void setAuthenticationToContext(Map<String, Object> claims){
        //JWT에서 파싱한 Claims 에서 username를 가져온다.
        String username = (String) claims.get("username");

        //JWT의 Claims에서 얻은 권한 정보를 기반으로 List<GrantedAuthority>를 생성
        //JwtAuthorityUtils클래스에서 createAuthorities(List<String> roles)메서드는 여기서 사용하기 위해 작성한것
        List<GrantedAuthority> authorities = authorityUtils.createAuthorities((List)claims.get("roles"));

        //username과 List<GrantedAuthority>를 포함한 Authentication 객체를 생성
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);

        //SecurityContext에 Authentication 객체를 저장
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
