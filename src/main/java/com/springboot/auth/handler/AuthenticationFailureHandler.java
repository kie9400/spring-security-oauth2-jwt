package com.springboot.auth.handler;

import com.springboot.auth.utils.ErrorResponder;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthenticationFailureHandler implements org.springframework.security.web.authentication.AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        ErrorResponder.sendErrorResponse(response, HttpStatus.UNAUTHORIZED);
    }

//    private void sendErrorResponse(HttpServletResponse response)throws IOException{
//        ErrorResponder.sendErrorResponse(response, HttpStatus.UNAUTHORIZED);
//
//        Gson gson = new Gson();     // Error 정보가 담긴 객체를 JSON 문자열로 변환하기 위한 인스턴스 생성
//        ErrorResponse errorResponse = ErrorResponse.of(HttpStatus.UNAUTHORIZED); // of메소드로 상태코드 전달
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);    // 클라이언트에게 타입을 알려줄 수 있도록 http 헤더에 추가
//        response.setStatus(HttpStatus.UNAUTHORIZED.value());          // 상태코드를 클라이언트에게 알려줄 수 있도록 http 헤더에 추가
//        response.getWriter().write(gson.toJson(errorResponse, ErrorResponse.class));   //ErrorReponse 객체를 JSON 포맷 문자열로 변환 후 출력 스트림 생성
//    }
}
