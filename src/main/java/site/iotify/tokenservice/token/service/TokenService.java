package site.iotify.tokenservice.token.service;

import site.iotify.tokenservice.security.PrincipalDetails;
import site.iotify.tokenservice.token.controller.dto.Token;

public interface TokenService {
    Token issueJwt(PrincipalDetails principalDetails);

    Token reissueToken(String accessToken, String refreshToken);

    void blackListToken(String accessToken, String refreshToken, String type);
}
