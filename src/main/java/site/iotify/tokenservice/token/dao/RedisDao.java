package site.iotify.tokenservice.token.dao;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Slf4j
@Component
@RequiredArgsConstructor
public class RedisDao {
    private final RedisTemplate<String, String> redisTemplate;

    public void saveToken(String key, String value, Duration duration) {
        redisTemplate.opsForValue().set(key, value, duration);
        log.info("[#] save token - key: {}, value: {}, duration: {}", key, value, duration);
    }

    public boolean hasToken(String key) {
        if (key == null) {
            return false;
        }
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    public String getToken(String key) {
        if (key == null) {
            return null;
        }
        return redisTemplate.opsForValue().get(key);
    }

    public void deleteToken(String token) {
        redisTemplate.delete(token);
    }
}
