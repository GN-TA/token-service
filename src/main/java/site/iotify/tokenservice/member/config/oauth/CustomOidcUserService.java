package site.iotify.tokenservice.member.config.oauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import site.iotify.tokenservice.member.config.auth.PrincipalDetails;
import site.iotify.tokenservice.member.dto.MemberInfo;

@Slf4j
@Service
public class CustomOidcUserService extends OidcUserService {

    /**
     * Google OAuth 인증을 처리하며, Google 서버로부터 사용자 정보를 가져와
     * 사용자 정보를 담은 {@link PrincipalDetails} 객체를 생성하여 반환합니다.
     *
     * @param userRequest Google OAuth 인증 요청 정보를 담은 객체
     * @return 인증된 사용자 정보를 담은 {@link PrincipalDetails} 객체
     * @throws OAuth2AuthenticationException OAuth2 인증 과정에서 오류가 발생한 경우
     */
    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        log.debug("userRequest: {}", userRequest);
        log.debug("accessToken: {}", userRequest.getAccessToken());
        log.debug("clientRegistration: {}", userRequest.getClientRegistration());

        OidcUser oidcUser = super.loadUser(userRequest);
        log.debug("oidcUser: {}", oidcUser.getAttributes());

        String provider = userRequest.getClientRegistration().getRegistrationId();
        if (!provider.equals("google")) {
            throw new OAuth2AuthenticationException("OAuth 로그인은 google만 제공함");
        }

        String userId = "google_" + oidcUser.getAttribute("sub");

        // TODO user-service에 userId로 검색해서 회원 정보 가져오기
        MemberInfo memberInfo = null;
        if (memberInfo == null) {
            // user-service 회원가입 요청 보내기
        }

        return new PrincipalDetails(memberInfo);
    }
}
