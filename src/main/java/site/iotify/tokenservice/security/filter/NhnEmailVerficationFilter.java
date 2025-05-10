package site.iotify.tokenservice.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import site.iotify.tokenservice.token.dao.RedisDao;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class NhnEmailVerficationFilter extends OncePerRequestFilter {
    private final RedisDao redisDao;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (request.getRequestURI().startsWith("/oauth2/authorization")
                && "signup".equals(request.getParameter("accessType"))) {
            String nhnEmail = request.getParameter("nhnEmail");
            String verified = redisDao.getToken(nhnEmail);
            if (!"true".equals(verified)) {
                response.setContentType("text/html;charset=UTF-8");
                response.getWriter().write(
                        "<script>"
                                + "alert('NHN 이메일 인증을 먼저 해주세요');"
                                + "window.location.href = '/v1/login';"
                                + "window.close();"
                                + "</script>"
                );
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}
