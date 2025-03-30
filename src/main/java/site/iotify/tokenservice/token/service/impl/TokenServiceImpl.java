package site.iotify.tokenservice.token.service.impl;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import site.iotify.tokenservice.global.InTransitionException;
import site.iotify.tokenservice.global.InvalidToken;
import site.iotify.tokenservice.security.PrincipalDetails;
import site.iotify.tokenservice.token.controller.dto.Token;
import site.iotify.tokenservice.token.dao.RedisDao;
import site.iotify.tokenservice.token.service.TokenService;
import site.iotify.tokenservice.token.util.JwtUtils;
import site.iotify.tokenservice.user.dto.UserInfo;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
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
    public Token reissueToken(HttpServletResponse response, String accessToken, String refreshToken) throws IOException {
        String userId;
        try {
            userId = jwtUtils.extractUserId(refreshToken);
        } catch (RuntimeException e) {
            log.error(e.getMessage());
            throw new InvalidToken();
        }
        String storedToken = redisDao.getToken(userId);
        Collection authorities = (Collection) jwtUtils.getClaims(refreshToken).getPayload().get("roles");
        Token token;

        if (!redisDao.hasToken(accessToken) && jwtUtils.validateToken(refreshToken, storedToken)) {
            blackListToken(refreshToken, "reissue");
            redisDao.saveToken(accessToken, "in-transition", Duration.ofSeconds(3L));
            token = issueToken(userId, authorities);
            return token;
        } else if (redisDao.hasToken(accessToken) && "in-transition".equals(redisDao.getToken(accessToken))) {
            token = new Token(issueToken(userId, authorities).getAccessToken(), redisDao.getToken(userId));
            throw new InTransitionException(token);
        } else {
            redisDao.deleteToken(userId);
            throw new InvalidToken();
        }
    }

    @Override
    public void blackListToken(String refreshToken, String type) {
        redisDao.saveToken(refreshToken, type, jwtUtils.extractExpirationTime(refreshToken));
        String key = jwtUtils.extractUserId(refreshToken);
        if (redisDao.hasToken(key)) {
            redisDao.deleteToken(jwtUtils.extractUserId(refreshToken));
        }
    }

    private Token issueToken(String userId, Collection authorities) {
        log.debug("[#] Issuing token... : {}", userId);

        String accessToken = jwtUtils.generateAccessToken(userId, authorities);
        String refreshToken = jwtUtils.generateRefreshToken(userId, authorities);
        Duration expiration = jwtUtils.extractExpirationTime(refreshToken);

        log.debug("[#] expiration: {}", expiration);

        redisDao.saveToken(userId, refreshToken, expiration);

        log.debug("[#] issue Token successfully");
        return new Token(accessToken, refreshToken);
    }


}
