package site.iotify.tokenservice.token.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import site.iotify.tokenservice.security.PrincipalDetails;
import site.iotify.tokenservice.token.controller.dto.Token;
import site.iotify.tokenservice.global.InvalidToken;
import site.iotify.tokenservice.token.service.TokenService;
import site.iotify.tokenservice.token.dao.RedisDao;
import site.iotify.tokenservice.token.util.JwtUtils;
import site.iotify.tokenservice.user.dto.UserInfo;

import java.time.Duration;
import java.util.Collection;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {
    private final JwtUtils jwtUtils;
    private final RedisDao redisDao;

    @Override
    public Token issueJwt(PrincipalDetails principalDetails) {
        UserInfo user = principalDetails.getUser();
        return issueToken(user.getId(), principalDetails.getAuthorities());
    }

    @Override
    public Token reissueToken(String accessToken, String refreshToken) {
        String email = jwtUtils.extractEmail(accessToken);
        String storedToken = redisDao.getToken(email);

        if (jwtUtils.validateToken(refreshToken, storedToken)) {
            blackListToken(accessToken, "reissue");
            Collection authorities = (Collection) jwtUtils.getClaims(accessToken).getPayload().get("roles");
            return issueToken(email, authorities);
        } else {
            throw new InvalidToken();
        }
    }

    @Override
    public void blackListToken(String accessToken, String type) {
        redisDao.saveToken(accessToken, type, jwtUtils.extractExpirationTime(accessToken));
        String key = jwtUtils.extractEmail(accessToken);
        if (redisDao.hasToken(key)) {
            redisDao.deleteToken(jwtUtils.extractEmail(accessToken));
        }
    }

    private Token issueToken(String email, Collection authorities) {
        log.debug("[#] Issuing token... : {}", email);

        String accessToken = jwtUtils.generateAccessToken(email, authorities);
        String refreshToken = jwtUtils.generateRefreshToken(email);
        Duration expiration = jwtUtils.extractExpirationTime(refreshToken);

        log.debug("[#] expiration: {}", expiration);

        redisDao.saveToken(email, refreshToken, expiration);

        log.debug("[#] issue Token successfully");
        return new Token(accessToken, refreshToken);
    }


}
