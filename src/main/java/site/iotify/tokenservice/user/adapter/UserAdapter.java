package site.iotify.tokenservice.user.adapter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import site.iotify.tokenservice.user.dto.UserInfo;
import site.iotify.tokenservice.user.dto.UserRequestDto;

import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserAdapter {
    private final RestTemplate restTemplate;
    private final static String URL_PREFIX = "http://%s";

    @Value("${service.user-url}")
    private String host;

    public Optional<UserInfo> getUserInfo(String emailId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> request = new HttpEntity<>(headers);

        String url = String.format(URL_PREFIX + "/user?email=%s", host, emailId);

        try {
            ResponseEntity<UserInfo> response = restTemplate.exchange(
                    url, HttpMethod.GET, request, UserInfo.class
            );
            return Optional.ofNullable(response.getBody());
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                log.warn("UserInfo not found for email {}: {}", emailId, e.getMessage());
                return Optional.empty();
            }
            throw e;
        }
    }

    public Optional<String> getPassword(String email) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> request = new HttpEntity<>(headers);

        String url = String.format(URL_PREFIX + "/pwd?id=%s", host, email);
        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    request,
                    String.class
            );
            return Optional.ofNullable(response.getBody());
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                return Optional.empty();
            }
            throw e;
        }
    }

    public String registerUser(UserRequestDto.UserRegister userRegister) {
        System.out.println("asdf" + userRegister);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<UserRequestDto.UserRegister> httpEntity = new HttpEntity<>(userRegister, headers);

        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(String.format(URL_PREFIX, host))
                .path("/user");
        ResponseEntity<String> response = restTemplate.exchange(
                uriComponentsBuilder.toUriString(),
                HttpMethod.POST,
                httpEntity,
                new ParameterizedTypeReference<String>() {
                }
        );
        return response.getBody();
    }

}
