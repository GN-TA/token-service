package site.iotify.tokenservice.global;

import org.springframework.http.HttpStatus;

public class UserNotFoundException extends AbstractApiException {
    public UserNotFoundException(String s) {
        super(s);
    }

    @Override
    public HttpStatus getHttpStatus() {
        return HttpStatus.NOT_FOUND;
    }
}
