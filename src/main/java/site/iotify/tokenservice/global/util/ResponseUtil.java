package site.iotify.tokenservice.global.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.io.IOException;

@NoArgsConstructor(access= AccessLevel.PRIVATE)
public class ResponseUtil {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static void serResponse(HttpServletResponse response, HttpStatus status, Object body) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(status.value());

        if (body != null) {
            String responseBody = objectMapper.writeValueAsString(body);
            response.getWriter().write(responseBody);
        }
    }
}
