package com.springboot.auth.utils;

import com.google.gson.Gson;
import com.springboot.response.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//ErrorResponse를 출력 스트림으로 생성하는 역할
public class ErrorResponder {
    public static void sendErrorResponse(HttpServletResponse response,
                                   HttpStatus status)throws IOException {
        Gson gson = new Gson();     // Error 정보가 담긴 객체를 JSON 문자열로 변환하기 위한 인스턴스 생성
        ErrorResponse errorResponse = ErrorResponse.of(status); // of메소드로 상태코드 전달
        //한글 깨짐 방지
        response.setCharacterEncoding("utf-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);    // 클라이언트에게 타입을 알려줄 수 있도록 http 헤더에 추가
        response.setStatus(status.value());          // 상태코드를 클라이언트에게 알려줄 수 있도록 http 헤더에 추가
        response.getWriter().write(gson.toJson(errorResponse, ErrorResponse.class));   //ErrorReponse 객체를 JSON 포맷 문자열로 변환 후 출력 스트림 생성
    }
}
