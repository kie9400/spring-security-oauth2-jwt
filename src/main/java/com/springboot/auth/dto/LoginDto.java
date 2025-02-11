package com.springboot.auth.dto;

import lombok.Getter;

//로그인 인증 정보를 역직렬화하기 위한 클래스
//단순히 ID/PW 정보만 담아 수신
@Getter
public class LoginDto {
    private String username;
    private String password;
}
