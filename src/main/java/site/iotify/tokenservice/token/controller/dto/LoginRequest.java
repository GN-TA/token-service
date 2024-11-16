package site.iotify.tokenservice.token.controller.dto;

import lombok.Getter;

@Getter
public class LoginRequest {
    private String loginId;
    private String password;
}
