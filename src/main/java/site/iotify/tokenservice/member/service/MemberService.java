package site.iotify.tokenservice.member.service;

import site.iotify.tokenservice.member.dto.MemberInfo;

public interface MemberService {
    boolean validateLogin(String loginId, String password);

    MemberInfo getMemberInfo(String loginId);
}
