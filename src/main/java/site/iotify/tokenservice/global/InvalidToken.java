package site.iotify.tokenservice.global;

import org.springframework.http.HttpStatus;

public class InvalidToken extends AbstractApiException {
    private static final HttpStatus STATUS = HttpStatus.UNAUTHORIZED;

    public InvalidToken(){
        super();
    }
    public InvalidToken(String message) {
        super(message);
    }

    @Override
    public HttpStatus getHttpStatus() {
        return STATUS;
    }
}
