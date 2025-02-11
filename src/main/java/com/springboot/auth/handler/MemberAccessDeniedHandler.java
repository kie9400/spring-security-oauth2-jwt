package com.springboot.auth.handler;

import com.springboot.auth.utils.ErrorResponder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


//인증에는 성공했지만 해당 리소스에 대한 권한이 없으면 호출되는 핸들러(검증 실패)

@Slf4j
@Component
public class MemberAccessDeniedHandler implements AccessDeniedHandler {
    //요청한 리소스에 대한 권한이없을 경우 발생하는 예외(AccessDeniedException) 처리 로직
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        //서버에 클라이언트의 요청은 도달했으나, 서버가 클라의 접근을 거부할 때 반환하는 코드 : FORBIDDEN
        ErrorResponder.sendErrorResponse(response, HttpStatus.FORBIDDEN);
        log.warn("Forbidden error happened: {}", accessDeniedException.getMessage());
    }
}
