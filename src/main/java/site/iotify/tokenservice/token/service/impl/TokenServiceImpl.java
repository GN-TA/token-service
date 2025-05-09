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
import site.iotify.tokenservice.user.exception.UnauthenticatedException;

import java.io.IOException;
import java.time.Duration;
import java.util.Collection;
import java.util.Objects;

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
    public Token reissueToken(HttpServletResponse response, String accessToken) throws IOException {
        String userId;
        try {
            userId = jwtUtils.extractUserId(accessToken);
        } catch (RuntimeException e) {
            log.error(e.getMessage());
            throw new InvalidToken();
        }
        Collection authorities = (Collection) jwtUtils.extractClaimsEvenIfExpired(accessToken).get("roles");
        Token token;
        String refreshToken = redisDao.getToken(accessToken);
        if (Objects.isNull(refreshToken)) {
            throw new UnauthenticatedException("다시 로그인 해주세요");
        }
        // refresh 검증 성공시 새 access token 생성 -> 이전 액세스 토큰 삭제 & 새 access : refresh 저장,
        // 실패 시 401
        if (jwtUtils.validateToken(refreshToken)) {
            redisDao.deleteToken(accessToken);
            token = issueToken(userId, authorities);
            return token;
        } else {
            throw new InvalidToken();
        }
    }

    @Override
    public void blackListToken(String key, String accessToken, Duration duration) {
        redisDao.saveToken(key + "-blacklisted", accessToken, duration);
    }

    private Token issueToken(String userId, Collection authorities) {
        log.debug("[#] Issuing token... : {}", userId);

        String accessToken = jwtUtils.generateAccessToken(userId, authorities);
        String refreshToken = jwtUtils.generateRefreshToken(userId, authorities);
        Duration expiration = jwtUtils.extractExpirationTime(refreshToken);

        log.debug("[#] expiration: {}", expiration);

        redisDao.saveToken(accessToken, refreshToken, expiration);

        log.debug("[#] issue Token successfully");
        return new Token(accessToken, refreshToken);
    }

}
