package com.springboot.oauth2_jwt.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
//사용자의 권한을 생성하기 위한 클래스
public class JwtAuthorityUtils {
    @Value("${mail.address.admin}")
    private String adminMailAddress;

    //Spring Security에서 지원하는 AuthorityUtils 클래스를 이용해 권한목록을 객체로 생성
    private final List<GrantedAuthority> ADMIN_ROLES = AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER");
    private final List<GrantedAuthority> USER_ROLES = AuthorityUtils.createAuthorityList("ROLE_USER");

    private final List<String> ADMIN_ROLES_STRING = List.of("ADMIN", "USER");
    private final List<String> USER_ROLES_STRING = List.of("USER");

    //데이터베이스에 저장된 Role를 기반으로 권한 정보를 생성하는 메서드
    //Spring Security(Security Context)에서 사용가능한 리스트 형태로 변환할 때 사용한다.
    //SecurityContext에 Authentication 객체를 저장할 때 List<grantedAuthority>형태이어야 한다.
    public List<GrantedAuthority> createAuthorities(List<String> roles){
        List<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
        return authorities;
    }

    //데이터베이스에 권한을 저장하기 위한 메서드
    //JWT만 사용했을 때는 memberService에서 권한을 생성하였지만
    //OAuth2에서는 OAuth2MemberSuccessHandler클래스에서 권한을 생성할 것
    public List<String> createRoles(String email){
        if(email.equals(adminMailAddress)){
            return ADMIN_ROLES_STRING;
        }
        return USER_ROLES_STRING;
    }

    //이메일 주소받아서 권한 부여하는 메서드
    public List<GrantedAuthority> createAuthorities(String email){
        if(email.equals(adminMailAddress)){
            return ADMIN_ROLES;
        }
        return USER_ROLES;
    }
}
