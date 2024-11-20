package site.iotify.tokenservice.member.dto;

import lombok.Getter;

@Getter
public class MemberInfo {
    private Long id;
    private String name;
    private String email;
    private String password;
    private String provider;
    private String auth;
}
