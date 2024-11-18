package site.iotify.tokenservice.member.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

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
        // 사용자 정보 받아와서 PrincipalDetails 타입 객체 생성해서 리턴
        return null;
    }

}
