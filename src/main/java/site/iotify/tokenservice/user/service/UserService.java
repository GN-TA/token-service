package site.iotify.tokenservice.user.service;

import site.iotify.tokenservice.user.dto.UserInfo;
import site.iotify.tokenservice.user.dto.UserRequestDto;

public interface UserService {
    boolean validateLogin(String loginId, String password);

    UserInfo getMemberInfo(String loginId);

    String registerEmailUser(UserRequestDto.UserRegister userRegister);

    void registerSocialUser(String email, String nhnEmail, String name, String provider);
}
