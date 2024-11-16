package site.iotify.tokenservice.member.adapter;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
@RequiredArgsConstructor
public class MemberAdapter {
    private final RestTemplate restTemplate;

}
