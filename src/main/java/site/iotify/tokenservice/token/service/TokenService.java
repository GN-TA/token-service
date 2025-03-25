package site.iotify.tokenservice.token.service;

import jakarta.servlet.http.HttpServletResponse;
import site.iotify.tokenservice.security.PrincipalDetails;
import site.iotify.tokenservice.token.controller.dto.Token;

import java.io.IOException;

public interface TokenService {
    Token issueJwt(PrincipalDetails principalDetails);

    Token reissueToken(HttpServletResponse response, String accessToken, String refreshToken) throws IOException;

    void blackListToken(String accessToken, String type);
}
