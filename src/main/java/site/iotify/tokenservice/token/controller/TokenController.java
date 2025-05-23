package site.iotify.tokenservice.token.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import site.iotify.tokenservice.global.InvalidToken;
import site.iotify.tokenservice.global.util.CookieUtil;
import site.iotify.tokenservice.token.controller.dto.Token;
import site.iotify.tokenservice.token.service.TokenService;

import java.io.IOException;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/v1")
public class TokenController {
    private final TokenService tokenService;

    @PostMapping("/refresh")
    public ResponseEntity<Token> refresh(HttpServletRequest request, HttpServletResponse response) {
        String accessToken = CookieUtil.extractTokenFromCookies(request, "AT")
                .orElseThrow(() -> new InvalidToken("Access Token이 존재하지 않습니다"));

        log.debug("[#] AT: {}", accessToken);

        try {
            Token newToken = tokenService.reissueToken(response, accessToken);
            CookieUtil.setTokenCookie(response, newToken);

            return ResponseEntity.ok(newToken);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
