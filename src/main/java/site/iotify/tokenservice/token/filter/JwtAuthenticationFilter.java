package site.iotify.tokenservice.token.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import site.iotify.tokenservice.global.util.ResponseUtil;
import site.iotify.tokenservice.security.PrincipalDetails;
import site.iotify.tokenservice.token.controller.dto.Token;
import site.iotify.tokenservice.token.service.TokenService;

import java.io.IOException;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.debug("[#] 로그인 검증 중");

        String username;
        String password;

        try {
            // JSON 형식 요청일 경우
            if (request.getContentType() != null && request.getContentType().contains("application/json")) {
                Map<String, String> requestBody = objectMapper.readValue(request.getInputStream(), Map.class);
                username = requestBody.get("email");  // 클라이언트가 email 키로 보낸 경우
                password = requestBody.get("password");
            } else {
                // Form 형식 요청일 경우
                username = request.getParameter("email"); // 기존 request.getParameter() 방식 유지
                password = request.getParameter("password");
            }
            log.debug("[#] username: {}", username);
            log.debug("[#] password: {}", password);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    username,
                    password
            );

            return authenticationManager.authenticate(authenticationToken);
        } catch (IOException e) {
            throw new AuthenticationException("입력 값을 읽을 수 없습니다") {};
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        log.debug("`[#] Login Success : {}", principalDetails.getUsername());
        Token token = tokenService.issueJwt(principalDetails);
        log.debug("[#] access token: {}", token.getAccessToken());
        log.debug("[#] refresh token: {}", token.getRefreshToken());

        response.addHeader("Set-Cookie", "AT=" + token.getAccessToken() + "; Path=/; SameSite=Strict");
        response.addHeader("Set-Cookie", "RT=" + token.getRefreshToken() + "; Path=/; SameSite=Strict");
        log.debug("[#] Add Set Cookie Header");

        ResponseUtil.serResponse(response, HttpStatus.OK, token);
    }

}
