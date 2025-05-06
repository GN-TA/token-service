//package site.iotify.tokenservice.security.oauth;
//
//import jakarta.servlet.ServletContext;
//import jakarta.servlet.http.HttpServletRequest;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
//import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
//import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
//import org.springframework.security.oauth2.core.oidc.user.OidcUser;
//import org.springframework.stereotype.Service;
//import org.springframework.web.context.request.RequestContextHolder;
//import org.springframework.web.context.request.ServletRequestAttributes;
//import site.iotify.tokenservice.security.PrincipalDetails;
//import site.iotify.tokenservice.user.adapter.UserAdapter;
//import site.iotify.tokenservice.user.dto.UserInfo;
//import site.iotify.tokenservice.user.dto.UserRequestDto;
//import site.iotify.tokenservice.user.service.UserService;
//
//import java.util.Objects;
//import java.util.UUID;
//
//@Slf4j
//@Service
//@RequiredArgsConstructor
//public class CustomOidcUserService extends OidcUserService {
//    private final UserAdapter userAdapter;
//    private final UserService userService;
//
//    /**
//     * Google OAuth 인증을 처리하며, Google 서버로부터 사용자 정보를 가져와
//     * 사용자 정보를 담은 {@link PrincipalDetails} 객체를 생성하여 반환합니다.
//     *
//     * @param userRequest Google OAuth 인증 요청 정보를 담은 객체
//     * @return 인증된 사용자 정보를 담은 {@link PrincipalDetails} 객체
//     * @throws OAuth2AuthenticationException OAuth2 인증 과정에서 오류가 발생한 경우
//     */
//    @Override
//    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
//        log.debug("[#] userRequest: {}", userRequest);
//        log.debug("[#] accessToken: {}", userRequest.getAccessToken());
//        log.debug("[#] clientRegistration: {}", userRequest.getClientRegistration());
//
//        OidcUser oidc = super.loadUser(userRequest);
//        log.debug("[#] oidcUser: {}", oidc.getAttributes());
//
//        String provider = userRequest.getClientRegistration().getRegistrationId(); // google
//        String sub = oidc.getAttribute("sub");                             // 구글 고유 ID
//        String userId = provider + "_" + sub;                                 // ex: google_1234567890
//        String email = oidc.getAttribute("email");
//        String name = oidc.getAttribute("name");
//
//        UserInfo userInfo = userAdapter.getUserInfo(email).orElse(null);
//        String password = userAdapter.getPassword(email).orElse(null);
//        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
//        if (attributes != null) {
//            HttpServletRequest request = attributes.getRequest();
//            String nhnEmail = (String) request.getSession().getAttribute("NHN_EMAIL_FOR_SOCIAL");
//            if (Objects.isNull(userInfo)) {
//                userService.registerSocialUser(email, nhnEmail, name, provider);
//            }
//        }
//        return new PrincipalDetails(userInfo, password);
//    }
//}
