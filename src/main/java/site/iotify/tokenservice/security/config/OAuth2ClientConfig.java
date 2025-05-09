package site.iotify.tokenservice.security.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class OAuth2ClientConfig {

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
