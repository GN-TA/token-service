package site.iotify.tokenservice.global;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import site.iotify.tokenservice.token.controller.dto.Token;

@Getter
public class InTransitionException extends AbstractApiException {
    private Token token;

    public InTransitionException() {
        super();
    }

    public InTransitionException(Token token) {
        this.token = token;
    }

    @Override
    public HttpStatus getHttpStatus() {
        return HttpStatus.ACCEPTED;
    }

}
