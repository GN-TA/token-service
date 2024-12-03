package site.iotify.tokenservice.user.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import site.iotify.tokenservice.user.adapter.UserAdapter;
import site.iotify.tokenservice.user.dto.UserInfo;
import site.iotify.tokenservice.user.service.UserService;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserAdapter userAdapter;

    @Override
    public boolean validateLogin(String loginId, String password) {
        return false;
    }

    @Override
    public UserInfo getMemberInfo(String loginId) {
        return null;
    }
}
