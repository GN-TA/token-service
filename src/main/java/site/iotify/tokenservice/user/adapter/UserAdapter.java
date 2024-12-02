package site.iotify.tokenservice.user.adapter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import site.iotify.tokenservice.user.dto.UserInfo;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserAdapter {
    private final RestTemplate restTemplate;

    @Value("${user.host}")
    private String host;

    @Value("${user.port}")
    private int port;

    public UserInfo getUserInfo(String emailId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> request = new HttpEntity<>(headers);
        String url = String.format("http://%s:%d/user?email=%s", host, port, emailId);

        ResponseEntity<UserInfo> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                request,
                UserInfo.class
        );

        return response.getBody();
    }

    public String getPassword(String email) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> request = new HttpEntity<>(headers);

        String url = String.format("http://%s:%d/pwd?id=%s", host, port, email);

        ResponseEntity<String> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                request,
                String.class
        );

        return response.getBody();
    }

}
