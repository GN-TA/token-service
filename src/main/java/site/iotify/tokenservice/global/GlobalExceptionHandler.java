package site.iotify.tokenservice.global;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.RequestContextHolder;
import site.iotify.tokenservice.global.util.CookieUtil;
import site.iotify.tokenservice.token.controller.dto.Token;
import site.iotify.tokenservice.user.exception.UnauthenticatedException;

import java.io.IOException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AbstractApiException.class)
    public ResponseEntity<String> apiExceptionHandler(AbstractApiException e) {
        return new ResponseEntity<>(e.getMessage(), e.getHttpStatus());
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus
    public ResponseEntity<String> unknownExceptionHandler(Exception e) {
        return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(InvalidToken.class)
    public ResponseEntity<String> handleInvalidRefreshToken(HttpServletResponse response, InvalidToken e) throws IOException {
        CookieUtil.clearTokenCookie(response);
        return new ResponseEntity<>("Invalid refresh token", HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(InTransitionException.class)
    public ResponseEntity<Token> handleInTransitionException(InTransitionException e) {
        return ResponseEntity.status(e.getHttpStatus()).body(e.getToken());
    }

    @ExceptionHandler(UnauthenticatedException.class)
    public ResponseEntity<String> handleUnauthorizedException(UnauthenticatedException e) {
        return ResponseEntity.status(e.getHttpStatus()).body(e.getMessage());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<String> handleUserNotFoundException(UserNotFoundException e) {
        return ResponseEntity.status(e.getHttpStatus()).body(e.getMessage());
    }
}
