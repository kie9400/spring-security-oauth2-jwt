package com.springboot.oauth2_jwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

@Component
public class JwtTokenizer {
    @Getter
    @Value("${jwt.key.secret}")
    private String secretKey;

    @Getter
    @Value("${jwt.access-token-expiration-minutes}")
    private int accessTokenExpirationMinutes;

    @Getter
    @Value("${jwt.refresh-token-expiration-minutes}")
    private int refreshTokenExpirationMinutes;

    //시크릿 키를 인코딩하기 위한 메서드
    public String encodeBase64SecretKey(String secretKey){
        return Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    //시크릿 키를 디코딩 하여 Key타입으로 반환하기 위한 메서드
    private Key getKeyFromBase64EncodedKey(String base64EncodedSecretKey){
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        //byte[] 배열을 HMAC-SHA에 적합한 암호화 키로 생성
        Key key = Keys.hmacShaKeyFor(keyBytes);

        //여기서 반환한 key는 JWT를 서명하거나 검증할 때 사용한다.
        return key;
    }

    //액세스 토큰 생성 메서드
    public String generateAccessToken(Map<String, Object> claims,
                                      String subject,
                                      Date expiration,
                                      String base64EncodedSecretKey){
        //받아온 key값을 디코딩하여 Key 타입으로 변환
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }

    //리플래쉬 토큰 생성 메서드
    public String generateRefreshToken(String subject,
                                      Date expiration,
                                      String base64EncodedSecretKey){
        //받아온 key값을 디코딩하여 Key 타입으로 변환
        Key key = getKeyFromBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration)
                .signWith(key)
                .compact();
    }

    //검증 후, Claims를 반환하기 위한 메서드
    public Jws<Claims> getClaims(String jws, String base64EncodedSceretKey){
        Key key = getKeyFromBase64EncodedKey(base64EncodedSceretKey);

        Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jws);

        return claims;
    }

    //단순히 검증만 하는 용도
    public void verifySignature(String jws, String bas64EncodedSecretKey){
        Key key = getKeyFromBase64EncodedKey(bas64EncodedSecretKey);

        Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jws);
    }

    //토큰 만료 기간
    public Date getTokenExpiration(int expirationMinutes) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, expirationMinutes);
        Date expiration = calendar.getTime();

        return expiration;
    }
}
