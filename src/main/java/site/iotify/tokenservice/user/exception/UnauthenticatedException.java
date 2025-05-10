package site.iotify.tokenservice.user.exception;

import org.springframework.http.HttpStatus;
import site.iotify.tokenservice.global.AbstractApiException;

public class UnauthenticatedException extends AbstractApiException {
    public UnauthenticatedException(String e) {
        super(e);
    }

    @Override
    public HttpStatus getHttpStatus() {
        return HttpStatus.UNAUTHORIZED;
    }
}
