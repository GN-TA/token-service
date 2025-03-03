package site.iotify.tokenservice.token.handler;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import site.iotify.tokenservice.global.InvalidToken;
import site.iotify.tokenservice.global.LogoutFailedException;
import site.iotify.tokenservice.global.util.CookieUtil;
import site.iotify.tokenservice.token.service.TokenService;


@Slf4j
@RequiredArgsConstructor
public class JwtLogoutHandler implements LogoutHandler {
    private final TokenService tokenService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        log.debug("[#] Logout..");
        try {

            String accessToken = CookieUtil.extractTokenFromCookies(request, "AT").orElseThrow(() -> new InvalidToken("Access token 이 존재하지 않습니다"));
            tokenService.blackListToken(accessToken, "logout");

            CookieUtil.clearTokenCookie(response);

            response.setStatus(HttpServletResponse.SC_OK);
        } catch (Exception e) {
            throw new LogoutFailedException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }

        log.debug("[#] Logout successful.");
    }


}
