package site.iotify.tokenservice.security.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import site.iotify.tokenservice.security.PrincipalDetails;
import site.iotify.tokenservice.user.adapter.UserAdapter;
import site.iotify.tokenservice.user.dto.UserInfo;

import java.util.Collections;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserAdapter userAdapter;
    /**
     * user-service에 요청을 보내 사용자의 정보를 조회하고, 해당 정보를 기반으로
     * {@link PrincipalDetails} 객체를 생성하여 반환합니다.
     *
     * 사용자가 존재하지 않을 경우 {@link UsernameNotFoundException}을 발생시킵니다.
     *
     * @param username 조회할 사용자의 아이디(이름)
     * @return 조회된 사용자 정보를 기반으로 생성된 {@link PrincipalDetails} 객체
     * @throws UsernameNotFoundException 사용자가 존재하지 않을 경우 발생
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // TODO 사용자 정보 받아와서 PrincipalDetails 타입 객체 생성해서 리턴
        log.info("[#] PrincipalDetails 생성중: {}", username);
        UserInfo userInfo = userAdapter.getUserInfo(username);
        if (userInfo == null) {
            throw new UsernameNotFoundException(username);
        }

        String password = userAdapter.getPassword(userInfo.getEmail());

        log.info("[#] UserInfo : {}", userInfo.toString());
        return new PrincipalDetails(userInfo, password);
    }

}
