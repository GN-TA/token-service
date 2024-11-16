package site.iotify.tokenservice.token.service;

import site.iotify.tokenservice.token.controller.dto.Token;

public interface TokenService {
    Token issueJwt(String loginId, String password);

    Token reissueToken(String accessToken, String refreshToken);
}
