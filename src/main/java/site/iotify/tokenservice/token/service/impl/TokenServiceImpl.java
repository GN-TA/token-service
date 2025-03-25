package site.iotify.tokenservice.token.service.impl;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import site.iotify.tokenservice.global.InvalidToken;
import site.iotify.tokenservice.security.PrincipalDetails;
import site.iotify.tokenservice.token.controller.dto.Token;
import site.iotify.tokenservice.token.dao.RedisDao;
import site.iotify.tokenservice.token.service.TokenService;
import site.iotify.tokenservice.token.util.JwtUtils;
import site.iotify.tokenservice.user.dto.UserInfo;

import java.io.IOException;
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
    public Token reissueToken(HttpServletResponse response, String accessToken, String refreshToken) throws IOException {
        String email = jwtUtils.extractEmail(refreshToken);
        System.out.println("ㅁㄴㅇㄹㅁㅁ " + email);
        String storedToken = redisDao.getToken(email);
        System.out.println("ㅁㄴㅇㄹf " + storedToken);

        if (jwtUtils.validateToken(refreshToken, storedToken)) {
            System.out.println("밸리데이트토큰 성공");
            blackListToken(refreshToken, "reissue");
            Collection authorities = (Collection) jwtUtils.getClaims(refreshToken).getPayload().get("roles");
            return issueToken(email, authorities);
        } else {
            // todo 레디스 email : refreshToken 삭제
            System.out.println("밸리데이트 실패");
            redisDao.deleteToken(email);
//            response.sendRedirect("/login");
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
        String refreshToken = jwtUtils.generateRefreshToken(email, authorities);
        Duration expiration = jwtUtils.extractExpirationTime(refreshToken);

        log.debug("[#] expiration: {}", expiration);

        redisDao.saveToken(email, refreshToken, expiration);

        log.debug("[#] issue Token successfully");
        return new Token(accessToken, refreshToken);
    }


}
