package site.iotify.tokenservice.token.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import site.iotify.tokenservice.global.LogoutFailedException;
import site.iotify.tokenservice.global.util.CookieUtil;
import site.iotify.tokenservice.token.dao.RedisDao;


@Slf4j
@Component
@RequiredArgsConstructor
public class JwtLogoutHandler implements LogoutHandler {
    private final RedisDao redisDao;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        log.debug("[#] Logout..");
        try {
            String accessToken = CookieUtil.extractTokenFromCookies(request, "AT").orElse(null);
            redisDao.deleteToken(accessToken);
            CookieUtil.clearTokenCookie(response);
            response.setStatus(HttpServletResponse.SC_OK);
        } catch (Exception e) {
            throw new LogoutFailedException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
        log.debug("[#] Logout successful.");
    }

}
