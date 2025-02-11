package com.springboot.oauth2_jwt;

import com.springboot.member.entity.Member;
import com.springboot.member.service.MemberService;
import com.springboot.oauth2_jwt.jwt.JwtTokenizer;
import com.springboot.oauth2_jwt.utils.JwtAuthorityUtils;
import com.springboot.stamp.Stamp;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


//OAuth2 인증에 성공하면 호출되는 핸들러
//JWT를 생성하고, 앞단(프론트)에 JWT를 전송하기 위해 리다이렉트하는 로직을 구현
//SimpleUrlAuthenticationSuccessHandler를 상속하면 리다이렉트를 할 수 있는 API 사용가능
public class OAuth2MemberSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    //JWT 토큰을 생성하기 위해 DI
    private final JwtTokenizer jwtTokenizer;
    //권한 정보를 생성하기 위해 DI
    private final JwtAuthorityUtils authorityUtils;
    //DB에 저장하기 위해 DI
    private final MemberService memberService;

    public OAuth2MemberSuccessHandler(JwtTokenizer jwtTokenizer, JwtAuthorityUtils authorityUtils, MemberService memberService) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
        this.memberService = memberService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        var oAuth2User = (OAuth2User)authentication.getPrincipal();
        //Authentication 객체로부터 얻어낸 oAuth2User 객체로부터 Resource Owner의 이메일 주소를 얻어온다.
        String email = String.valueOf(oAuth2User.getAttributes().get("email"));

        //AuthorityUtils를 이용해 권한 정보를 생성한다.
        List<String> authorities = authorityUtils.createRoles(email);

        //Resource Owner의 이메일 주소를 데이터베이스 저장
        //애플리케이션의 리소스와 연관 관계를 맺기 위해 최소한의 정보만 애플리케이션에서 관리한다.
        Member member = new Member(email);
        member.setStamp(new Stamp());
        memberService.createMember(member);

        //액세스 토큰과 리플래시 토큰을 생성해서 프론트엔드 애플리케이션에 전달하기 위해 리다이렉트
        redirect(request, response, email, authorities);
    }

    //액세스 토큰과 리플래시 토큰을 생성하여 프론트에게 리다이렉트 하는 메서드
    //프론트 URL을 액세스 토큰과 리플래시 토큰을 포함하여 생성한다.
    private void redirect(HttpServletRequest request, HttpServletResponse
            response, String username, List<String> authorities) throws IOException {
        String accessToken = delegateAccessToken(username, authorities);
        String refreshToken = delegateRefreshToken(username);

        String url = createUrl(accessToken, refreshToken).toString();
        //부모 클래스에서 제공하는 메서드들을 이용해 프론트엔드 애플리케이션 쪽으로 리다이렉트
        getRedirectStrategy().sendRedirect(request, response, url);
    }

    //JWT Access Token를 생성하는 메서드
    private String delegateAccessToken(String username, List<String> authorities){
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", username);
        claims.put("roles", authorities);

        String subject = username;
        //액세스 토큰 만료시간 가져옴
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getAccessTokenExpirationMinutes());
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);
        return accessToken;
    }

    private String delegateRefreshToken(String username){
        String subject = username;
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getRefreshTokenExpirationMinutes());
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String refreshToKen = jwtTokenizer.generateRefreshToken(subject,expiration,base64EncodedSecretKey);
        return refreshToKen;
    }

    private URI createUrl(String accessToken, String refreshToken){
        MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
        queryParams.add("access_token",accessToken);
        queryParams.add("refresh_token",refreshToken);

        //UriComponentsBuilder를 이용해 Access Token과 Refresh Token을 포함한 URL을 생성
        return UriComponentsBuilder
                .newInstance()
                .scheme("http")
                .host("localhost")
                //port의 기본값은 80으로, 설정하지 않으면 80
                .port(80)
                .path("/receive-token.html")
                .queryParams(queryParams)
                .build()
                .toUri();
    }
}
