package site.iotify.tokenservice.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import site.iotify.tokenservice.user.dto.DoorayResponse;

@Component
@RequiredArgsConstructor
public class DoorayService {
    @Value("${dooray.api.token}")
    private String token;
    @Value("${dooray.api.host}")
    private String host;

    private final RestTemplate restTemplate;

    public DoorayResponse.DoorayMemberResponse getUserInfo(String externalEmailAddress) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", String.format("dooray-api %s", token));
        HttpEntity<Void> httpEntity = new HttpEntity<>(headers);
        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(host)
                .path("common/v1/members")
                .queryParam("externalEmailAddresses", externalEmailAddress);

        ResponseEntity<DoorayResponse.DoorayMemberResponse> response = restTemplate.exchange(
                uriComponentsBuilder.toUriString(),
                HttpMethod.GET,
                httpEntity,
                new ParameterizedTypeReference<DoorayResponse.DoorayMemberResponse>() {
                }
        );
        DoorayResponse.DoorayMemberResponse doorayMemberResponse = response.getBody();
        return doorayMemberResponse;
    }

    public boolean isNHNMember(String externalEmailAddress) {
        DoorayResponse.DoorayMemberResponse doorayMemberResponse = getUserInfo(externalEmailAddress);
        if (doorayMemberResponse.getTotalCount() == 0) {
            throw new IllegalArgumentException();
        }
        for (DoorayResponse.Result result : doorayMemberResponse.getResult()) {
            if (externalEmailAddress.equals(result.getExternalEmailAddress())) {
                return true;
            }
        }
        return false;
    }
}
