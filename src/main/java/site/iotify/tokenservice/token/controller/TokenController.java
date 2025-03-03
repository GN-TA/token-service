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

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/v1")
public class TokenController {
    private final TokenService tokenService;

    @PostMapping("/refresh")
    public ResponseEntity<Token> refresh(HttpServletRequest request, HttpServletResponse response) {
        String accessToken = CookieUtil.extractTokenFromCookies(request, "AT").orElseThrow(() -> new InvalidToken("Access Token이 존재하지 않습니다"));
        String refreshToken = CookieUtil.extractTokenFromCookies(request, "RT").orElseThrow(() -> new InvalidToken("Refresh Token이 존재하지 않습니다"));

        log.debug("[#] AT: {}", accessToken);
        log.debug("[#] RT: {}", refreshToken);

        try {
            Token newToken = tokenService.reissueToken(accessToken, refreshToken);
            CookieUtil.setTokenCookie(response, newToken);

            return ResponseEntity.ok(newToken);

        } catch (InvalidToken e) {

            return ResponseEntity.badRequest().build();
        }
    }

}
