package site.iotify.tokenservice.token.exception;

import org.springframework.http.HttpStatus;

public class LoginFailedException extends AbstractApiException {
    private static final HttpStatus STATUS = HttpStatus.BAD_REQUEST;

    public LoginFailedException(String msg) {
        super(msg);
    }

    @Override
    public HttpStatus getHttpStatus() {
        return STATUS;
    }
}
