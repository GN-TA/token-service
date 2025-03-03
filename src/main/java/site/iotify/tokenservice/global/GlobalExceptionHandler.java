package site.iotify.tokenservice.global;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import site.iotify.tokenservice.global.util.CookieUtil;

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
    public ResponseEntity<Void> handleInvalidRefreshToken(HttpServletResponse response, InvalidToken e) {
        CookieUtil.clearTokenCookie(response);

        return ResponseEntity.badRequest().build();
    }
}
