package site.iotify.tokenservice.token.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import site.iotify.tokenservice.token.controller.dto.Token;
import site.iotify.tokenservice.token.service.TokenService;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/token/v1")
public class TokenController {
    private final TokenService tokenService;

    @PostMapping("/refresh")
    public ResponseEntity<Token> refresh(@RequestHeader("Authorization") String authorization, @CookieValue String refreshToken) {
        log.debug("[#] Authorization header: {}", authorization);
        log.debug("[#] Refresh token: {}", refreshToken);
        if (authorization == null || refreshToken == null || !authorization.startsWith("Bearer ") || authorization.length() < 8) {
            return ResponseEntity.badRequest().build();
        }

        String accessToken = authorization.substring(7);
        Token newToken = tokenService.reissueToken(accessToken, refreshToken);
        return ResponseEntity.ok(newToken);
    }

}
