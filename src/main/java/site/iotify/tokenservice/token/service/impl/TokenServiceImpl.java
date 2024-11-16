package site.iotify.tokenservice.token.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import site.iotify.tokenservice.member.dto.MemberInfo;
import site.iotify.tokenservice.token.controller.dto.Token;
import site.iotify.tokenservice.token.exception.InvalidRefreshToken;
import site.iotify.tokenservice.token.exception.LoginFailedException;
import site.iotify.tokenservice.member.service.MemberService;
import site.iotify.tokenservice.token.service.TokenService;
import site.iotify.tokenservice.token.dao.RedisDao;
import site.iotify.tokenservice.token.util.JwtUtils;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {
    private final RedisDao redisDao;
    private final MemberService memberService;

    @Override
    public Token issueJwt(String loginId, String password) {
        if (loginId == null || loginId.isEmpty() || password == null || password.isEmpty()) {
            throw new LoginFailedException(loginId + ": id or password is empty");
        }

        if (memberService.validateLogin(loginId, password)) {
            MemberInfo memberInfo = memberService.getMemberInfo(loginId);

            return issueToken(String.valueOf(memberInfo.getId()));

        } else {
            throw new LoginFailedException(loginId + ": invalid password");
        }
    }

    @Override
    public Token reissueToken(String accessToken, String refreshToken) {
        String userId = JwtUtils.extractUserId(accessToken);
        String storedToken = redisDao.getToken(userId);

        if (JwtUtils.validateToken(refreshToken, storedToken)) {
            blackListToken(accessToken, refreshToken);
            return issueToken(userId);
        } else {
            throw new InvalidRefreshToken();
        }
    }

    private void blackListToken(String accessToken, String refreshToken) {
        redisDao.saveToken(accessToken, "", JwtUtils.extractExpirationTime(accessToken));
        redisDao.deleteToken(JwtUtils.extractUserId(refreshToken));
    }

    private Token issueToken(String id) {
        String accessToken = JwtUtils.generateAccessToken(id);
        String refreshToken = JwtUtils.generateRefreshToken(id);
        Duration expiration = JwtUtils.extractExpirationTime(refreshToken);

        redisDao.saveToken(id, refreshToken, expiration);
        return new Token(accessToken, refreshToken);
    }


}
