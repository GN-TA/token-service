package site.iotify.tokenservice.user.adapter;

import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import site.iotify.tokenservice.user.dto.UserInfo;

@Component
@RequiredArgsConstructor
public class UserAdapter {
    private final String USER_API_URL = "http://localhost:8090/";
    private final RestTemplate restTemplate;

    public UserInfo getUserInfo(String emailId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> request = new HttpEntity<>(headers);

        ResponseEntity<UserInfo> response = restTemplate.exchange(
                USER_API_URL + "user?email=" + emailId,
                HttpMethod.GET,
                request,
                UserInfo.class
        );

        return response.getBody();
    }

}
