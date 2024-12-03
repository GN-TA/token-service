package site.iotify.tokenservice.exception;

import org.springframework.http.HttpStatus;

public class LogoutFailedException extends AbstractApiException{
    private static HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

    public LogoutFailedException(String msg) {
        super(msg);
    }

    public LogoutFailedException(String msg, HttpStatus status) {
        super(msg);
        this.status = status;
    }

    @Override
    public HttpStatus getHttpStatus() {
        return status;
    }
}
