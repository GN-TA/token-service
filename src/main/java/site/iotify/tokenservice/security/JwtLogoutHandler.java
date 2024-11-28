package site.iotify.tokenservice.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import site.iotify.tokenservice.exception.LogoutFailedException;
import site.iotify.tokenservice.token.service.TokenService;

@Slf4j
@RequiredArgsConstructor
public class JwtLogoutHandler implements LogoutHandler {
    private final TokenService tokenService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        log.trace("[#] Logout..");
        try {
            String accessToken = request.getHeader("Authorization").substring(7);
            String refreshToken = null;
            for (Cookie cookie : request.getCookies()) {
                if ("refreshToken".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                }
            }

            tokenService.blackListToken(accessToken, refreshToken, "logout");

        } catch (NullPointerException e) {
            throw new LogoutFailedException(e.getMessage(), HttpStatus.BAD_REQUEST);
        }

        log.trace("[#] Logout successful.");
    }
}
