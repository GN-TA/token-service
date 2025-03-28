package site.iotify.tokenservice.global.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import site.iotify.tokenservice.token.controller.dto.Token;

import java.time.Duration;
import java.util.Optional;

public class CookieUtil {
    private static final int TOKEN_EXPIRES = (int) Duration.ofDays(7).getSeconds();

    public static Optional<String> extractTokenFromCookies(HttpServletRequest request, String cookieName) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }

        for (Cookie cookie : request.getCookies()) {
            if (cookieName.equals(cookie.getName())) {
                return Optional.of(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    public static void setTokenCookie(HttpServletResponse response, Token token) {
        response.addHeader("Set-Cookie", "AT=" + token.getAccessToken() + "; Path=/;  Max-Age=" + TOKEN_EXPIRES + "; SameSite=Strict");
        response.addHeader("Set-Cookie", "RT=" + token.getRefreshToken() + "; Path=/; Max-Age=" + TOKEN_EXPIRES + "; HttpOnly; SameSite=Strict");
    }

    public static void clearTokenCookie(HttpServletResponse response) {
        System.out.println("클리어 토큰 쿠키");
        response.addHeader("Set-Cookie", "AT=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
        response.addHeader("Set-Cookie", "RT=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
    }
}
