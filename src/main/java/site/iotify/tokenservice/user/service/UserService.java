package site.iotify.tokenservice.user.service;

import site.iotify.tokenservice.user.dto.UserInfo;

public interface UserService {
    boolean validateLogin(String loginId, String password);

    UserInfo getMemberInfo(String loginId);
}
