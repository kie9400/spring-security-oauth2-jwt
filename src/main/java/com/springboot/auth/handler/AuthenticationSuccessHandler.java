package com.springboot.auth.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//로그인 인증에 성공했을 때 추가처리를 위한 핸들러
@Slf4j
public class AuthenticationSuccessHandler implements org.springframework.security.web.authentication.AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
      log.info("# 로그인 인증 완료!!");
    }
}
