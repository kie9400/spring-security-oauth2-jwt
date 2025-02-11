package com.springboot.auth.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class AuthorityUtils {
    //설정파일(yml)에 추가한 프로퍼티 값을 가져온다.
    @Value("${mail.address.admin}")
    private String adminMailAddress;

    //스프링 시큐리티에서 지원하는 AuthorityUtils클래스로 사용 권한 목록 객체 생성
    //관리자의 권한목록 객체 생성
    private final List<GrantedAuthority> ADMIN_ROLE = org.springframework.security.core.authority.AuthorityUtils.createAuthorityList("ROLE_ADMIN","ROLE_USER");
    //일반 사용자의 권한목록 객체 생성
    private final List<GrantedAuthority> USER_ROLE = org.springframework.security.core.authority.AuthorityUtils.createAuthorityList("ROLE_USER");

    //데이터베이스에 권한 목록 정보를 저장하기 위한 필드 선언
    private final List<String>ADMIN_ROLES_STRING = List.of("ADMIN","USER");
    private final List<String> USER_ROLES_STRING = List.of("USER");

    //사용자의 권한을 데이터베이스에 저장하기 위한 메서드
    public List<String> createAuthorities(String email){
        if(email.equals(adminMailAddress)){
            return ADMIN_ROLES_STRING;
        }else {
            //아니라면 사용자의 권한만 부여한다.
            return USER_ROLES_STRING;
        }
    }

    //데이터베이스에 저장되어있는 권한정보 목록(Role)을 가져와 이를 기반으로 권한 정보를 생성한다.
    public List<GrantedAuthority> createAuthorities(List<String> roles){
        List<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
        return authorities;
    }
}
