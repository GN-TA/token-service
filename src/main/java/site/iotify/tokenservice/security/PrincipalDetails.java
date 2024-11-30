package site.iotify.tokenservice.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import site.iotify.tokenservice.user.dto.UserInfo;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public class PrincipalDetails implements UserDetails, OidcUser {

    private UserInfo userInfo;
    private String password;
    private Map<String, Object> attributes;
    private Map<String, Object> claims;
    private OidcUserInfo oidcUserInfo;
    private OidcIdToken oidcIdToken;

    /**
     * 일반 로그인 시 호출되는 생성자입니다.
     * @param userInfo
     */
    public PrincipalDetails(UserInfo userInfo, String password) {
        this.userInfo = userInfo;
        this.password = password;
    }

    /**
     * 구글 OAuth 로그인 시 호출되는 생성자입니다.
     * @param userInfo
     * @param attributes
     * @param claims
     * @param oidcUserInfo
     * @param oidcIdToken
     */
    public PrincipalDetails(UserInfo userInfo, String password, Map<String, Object> attributes, Map<String, Object> claims,
                            OidcUserInfo oidcUserInfo, OidcIdToken oidcIdToken) {
        this.userInfo = userInfo;
        this.password = password;
        this.attributes = attributes;
        this.claims = claims;
        this.oidcUserInfo = oidcUserInfo;
        this.oidcIdToken = oidcIdToken;
    }


    @Override
    public String getName() {
        return "";
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add((GrantedAuthority) () -> userInfo.getAuth());
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return userInfo.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Map<String, Object> getClaims() {
        return claims;
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return oidcUserInfo;
    }

    @Override
    public OidcIdToken getIdToken() {
        return oidcIdToken;
    }
}
