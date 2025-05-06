package site.iotify.tokenservice.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import site.iotify.tokenservice.token.dao.RedisDao;
import site.iotify.tokenservice.user.service.UserService;

import java.io.IOException;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class OAuth2ClientConfig {
    private final RedisDao redisDao;
    private final UserService userService;

    @Bean
    public OAuth2AuthorizationRequestResolver customAuthorizationRequestResolver(ClientRegistrationRepository clients) {
        DefaultOAuth2AuthorizationRequestResolver defaultResolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clients,
                        "/oauth2/authorization"
                );
        return new OAuth2AuthorizationRequestResolver() {
            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                return applyCustomLogic(
                        defaultResolver.resolve(request),
                        request
                );
            }

            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
                return applyCustomLogic(
                        defaultResolver.resolve(request, clientRegistrationId),
                        request
                );
            }

            private OAuth2AuthorizationRequest applyCustomLogic(
                    OAuth2AuthorizationRequest original,
                    HttpServletRequest request) {
                if (original == null) {
                    return null;
                }

                String accessType = request.getParameter("accessType");
                HttpSession session = request.getSession();
                if ("login".equals(accessType)) {
                    session.setAttribute("ACCESS_TYPE", "login");
                } else if ("signup".equals(accessType)) {
//                    String nhnVerified = redisDao.getToken(request.getParameter("nhnEmail"));
//                    if (!"true".equals(nhnVerified)) {
//                        HttpServletResponse response =
//                                ((ServletRequestAttributes) RequestContextHolder
//                                        .currentRequestAttributes()).getResponse();
//
//                        new SecurityContextLogoutHandler().logout(request, response, null);
//                        response.setContentType("text/html;charset=UTF-8");
//                        try {
//                            response.getWriter().write(
//                                    "<script>"
//                                            + " alert('NHN 이메일 인증을 먼저 해주세요');"
//                                            + " window.close();"
//                                            + "</script>"
//                            );
//                        } catch (IOException e) {
//                            throw new RuntimeException(e);
//                        }
//                        return null;
//                    }
                    String nhnEmailParam = request.getParameter("nhnEmail");
                    session.setAttribute("ACCESS_TYPE", "signup");
                    session.setAttribute("NHN_EMAIL_FOR_SOCIAL", nhnEmailParam);
                } else {
                    throw new IllegalArgumentException("잘못된 요청입니다.");
                }

                log.error("nhn 인증 성공 !");
                return OAuth2AuthorizationRequest.from(original)
                        .build();
            }
        };
    }
}
