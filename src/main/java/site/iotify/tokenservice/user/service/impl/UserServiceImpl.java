package site.iotify.tokenservice.user.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import site.iotify.tokenservice.token.dao.RedisDao;
import site.iotify.tokenservice.user.adapter.UserAdapter;
import site.iotify.tokenservice.user.dto.UserInfo;
import site.iotify.tokenservice.user.dto.UserRequestDto;
import site.iotify.tokenservice.user.exception.UnauthenticatedException;
import site.iotify.tokenservice.user.service.UserService;

import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserAdapter userAdapter;
    private final RedisDao redisDao;

    @Override
    public boolean validateLogin(String loginId, String password) {
        return false;
    }

    @Override
    public UserInfo getMemberInfo(String loginId) {
        return userAdapter.getUserInfo(loginId).orElse(null);
    }

    @Override
    public String registerEmailUser(UserRequestDto.UserRegister userRegister) {
        authenticateEmail(userRegister.getEmail(), userRegister.getEmailCode());
        authenticateNHNMail(userRegister.getNhnEmail());

        return userAdapter.registerUser(userRegister);
    }

    @Override
    public void registerSocialUser(String email, String nhnEmail, String name, String provider) {
        authenticateNHNMail(nhnEmail);
        System.out.println("qwer" + email + ", " + nhnEmail + ", " + name + ", " + provider);
        String password = UUID.randomUUID().toString();
        userAdapter.registerUser(UserRequestDto.UserRegister.builder()
                .email(email)
                .nhnEmail(nhnEmail)
                .name(name)
                .provider(provider)
                .password(password)
                .passwordConfirmation(password)
                .build()
        );
    }

    private void authenticateEmail(String email, String code) {
        if (email.isBlank() || code.isBlank()) {
            throw new IllegalArgumentException("올바른 이메일과 인증번호를 작성해주세요");
        }
        if (Objects.isNull(redisDao.getToken(email)) || !redisDao.getToken(email).equals(code)) {
            throw new UnauthenticatedException("메일이 올바르지 않습니다");
        }
    }

    private void authenticateNHNMail(String nhnMail) {
        if (nhnMail.isBlank()) {
            throw new IllegalArgumentException("올바른 이메일과 인증번호를 작성해주세요");
        }
        if (Objects.isNull(redisDao.getToken(nhnMail)) || !redisDao.getToken(nhnMail).equals("true")) {
            throw new UnauthenticatedException("NHN메일이 올바르지 않습니다");
        }
    }
}
