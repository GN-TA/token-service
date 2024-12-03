package site.iotify.tokenservice.user.dto;

import lombok.Getter;
import lombok.ToString;

@ToString
@Getter
public class UserInfo {
    private Long id;
    private String username;
    private String email;
    private String provider;
    private String auth;
}
