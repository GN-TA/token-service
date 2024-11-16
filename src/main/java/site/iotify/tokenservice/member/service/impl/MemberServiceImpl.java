package site.iotify.tokenservice.member.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import site.iotify.tokenservice.member.adapter.MemberAdapter;
import site.iotify.tokenservice.member.dto.MemberInfo;
import site.iotify.tokenservice.member.service.MemberService;

@Service
@RequiredArgsConstructor
public class MemberServiceImpl implements MemberService {
    private final MemberAdapter memberAdapter;
    private final PasswordEncoder passwordEncoder;


    @Override
    public boolean validateLogin(String loginId, String password) {
        return false;
    }

    @Override
    public MemberInfo getMemberInfo(String loginId) {
        return null;
    }
}
