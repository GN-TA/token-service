package site.iotify.tokenservice.token.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import site.iotify.tokenservice.token.controller.dto.LoginRequest;
import site.iotify.tokenservice.token.controller.dto.Token;
import site.iotify.tokenservice.token.service.TokenService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/token")
public class TokenController {
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<Token> login(@RequestBody LoginRequest req) {
        Token token = tokenService.issueJwt(req.getLoginId(), req.getPassword());
        return ResponseEntity.ok(token);
    }

    @PostMapping("/refresh")
    public ResponseEntity<Token> refresh(@RequestHeader("Authorization") String authorization, @CookieValue String refreshToken) {
        if (authorization != null && refreshToken != null && authorization.startsWith("Bearer ") && authorization.length() > 7) {
            return ResponseEntity.badRequest().build();
        }

        String accessToken = authorization.substring(7);
        Token newToken = tokenService.reissueToken(accessToken, refreshToken);
        return ResponseEntity.ok(newToken);
    }


}
