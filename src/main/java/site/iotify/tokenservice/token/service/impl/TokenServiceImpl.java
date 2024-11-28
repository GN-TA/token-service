package site.iotify.tokenservice.token.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import site.iotify.tokenservice.security.PrincipalDetails;
import site.iotify.tokenservice.token.controller.dto.Token;
import site.iotify.tokenservice.exception.InvalidRefreshToken;
import site.iotify.tokenservice.token.service.TokenService;
import site.iotify.tokenservice.token.dao.RedisDao;
import site.iotify.tokenservice.token.util.JwtUtils;

import java.time.Duration;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {
    private final JwtUtils jwtUtils;
    private final RedisDao redisDao;

    @Override
    public Token issueJwt(PrincipalDetails principalDetails) {
        return issueToken(String.valueOf(principalDetails.getUsername()));
    }

    @Override
    public Token reissueToken(String accessToken, String refreshToken) {
        String userId = jwtUtils.extractUserId(accessToken);
        String storedToken = redisDao.getToken(userId);

        if (jwtUtils.validateToken(refreshToken, storedToken)) {
            blackListToken(accessToken, refreshToken, "refresh");
            return issueToken(userId);
        } else {
            throw new InvalidRefreshToken();
        }
    }

    @Override
    public void blackListToken(String accessToken, String refreshToken, String type) {
        redisDao.saveToken(accessToken, type, jwtUtils.extractExpirationTime(accessToken));
        String key = jwtUtils.extractUserId(refreshToken);
        if (redisDao.hasToken(key)) {
            redisDao.deleteToken(jwtUtils.extractUserId(refreshToken));
        }
    }

    private Token issueToken(String id) {
        log.trace("[#] Issuing token... : {}", id);

        String accessToken = jwtUtils.generateAccessToken(id);
        String refreshToken = jwtUtils.generateRefreshToken(id);
        Duration expiration = jwtUtils.extractExpirationTime(refreshToken);

        log.debug("[#] expiration: {}", expiration);

        redisDao.saveToken(id, refreshToken, expiration);

        log.trace("[#] issue Token successfully");
        return new Token(accessToken, refreshToken);
    }


}
