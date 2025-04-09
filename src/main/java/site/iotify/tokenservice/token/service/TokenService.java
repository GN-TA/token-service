package site.iotify.tokenservice.token.service;

import jakarta.servlet.http.HttpServletResponse;
import site.iotify.tokenservice.security.PrincipalDetails;
import site.iotify.tokenservice.token.controller.dto.Token;

import java.io.IOException;
import java.time.Duration;

public interface TokenService {
    Token issueJwt(PrincipalDetails principalDetails);

    Token reissueToken(HttpServletResponse response, String accessToken) throws IOException;

    void blackListToken(String accessToken, String type, Duration duration);
}
