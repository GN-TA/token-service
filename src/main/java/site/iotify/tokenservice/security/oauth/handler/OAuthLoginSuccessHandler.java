package site.iotify.tokenservice.security.oauth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Component;
import site.iotify.tokenservice.global.UserNotFoundException;
import site.iotify.tokenservice.global.util.CookieUtil;
import site.iotify.tokenservice.global.util.ResponseUtil;
import site.iotify.tokenservice.security.PrincipalDetails;
import site.iotify.tokenservice.token.controller.dto.Token;
import site.iotify.tokenservice.token.filter.JwtAuthenticationFilter;
import site.iotify.tokenservice.token.service.TokenService;
import site.iotify.tokenservice.user.dto.UserInfo;
import site.iotify.tokenservice.user.service.DoorayService;
import site.iotify.tokenservice.user.service.UserService;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuthLoginSuccessHandler implements AuthenticationSuccessHandler {
    private final UserService userService;
    private final TokenService tokenService;
    @Value("${service.front-url}")
    private String frontUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.error("로그인 success");
        HttpSession session = request.getSession(false);
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        if ("login".equals(session.getAttribute("ACCESS_TYPE"))) {
            UserInfo userInfo = userService.getMemberInfo(oAuth2User.getAttribute("email"));
            if (Objects.isNull(userInfo)) {
                log.error("등록되지 않은 사용자");
                new SecurityContextLogoutHandler().logout(request, response, authentication);
                response.addHeader("Set-Cookie", "JSESSIONID; Path=/; Max-Age=0; SameSite=Strict");
                response.setContentType("text/html; charset=UTF-8");
                response.getWriter().write(
                        "<script>" +
                                "  alert('등록되지 않은 사용자입니다. 회원가입을 진행해주세요.');" +
                                "  window.close();" +
                                "</script>"
                );
                return;
            }
            Token token = tokenService.issueJwt(new PrincipalDetails(userInfo, ""));
            CookieUtil.setTokenCookie(response, token);
            response.setContentType("text/html; charset=UTF-8");
            response.getWriter().write(
                    "<script>" +
                            "  window.close();" +
                            "  window.opener.location.href = '" + frontUrl + "/';" +
                            "  window.opener.location.reload();" +
                            "</script>"
            );
        } else if ("signup".equals(session.getAttribute("ACCESS_TYPE"))
                && authentication instanceof OAuth2AuthenticationToken oauth) {
            String email = oAuth2User.getAttribute("email");
            String provider = oauth.getAuthorizedClientRegistrationId();
            String nhnEmail = (String) session.getAttribute("NHN_EMAIL_FOR_SOCIAL");

            userService.registerSocialUser(email, nhnEmail, oAuth2User.getName(), provider);

            UserInfo userInfo = userService.getMemberInfo(email);
            Token token = tokenService.issueJwt(new PrincipalDetails(userInfo, ""));
            CookieUtil.setTokenCookie(response, token);
            response.setContentType("text/html; charset=UTF-8");
            response.getWriter().write(
                    "<script>" +
                            "  window.close();" +
                            "  window.opener.location.href = '" + frontUrl + "/';" +
                            "  window.opener.location.reload();" +
                            "</script>"
            );
        }
    }
}
