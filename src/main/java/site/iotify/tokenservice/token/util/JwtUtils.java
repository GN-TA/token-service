package site.iotify.tokenservice.token.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtUtils {
    private static final long EXPIRATION_TIME_MS_ACCESS = 1000l * 60 * 60;
    private static final long EXPIRATION_TIME_MS_REFRESH = 1000l * 60 * 60 * 24 * 7;

    @Value("${jwt.private-key}")
    private String privateKey;

    @Value("${jwt.public-key}")
    private String publicKey;

    /**
     * Token 생성을 위한 private key 객체 생성
     * @return
     */
    private PrivateKey getPrivateKey() {
        String privateKeyPEM = privateKey
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("——END PRIVATE KEY——", "")
                .replaceAll("\\s", "");

        log.debug("[#] privateKeyPEM : {}", privateKeyPEM);

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }


    private PublicKey getPublicKey() {
        String publicKeyPEM = publicKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("——END PUBLIC KEY——", "")
                .replaceAll("\\s", "");

        log.debug("[#] publicKeyPEM : {}", publicKeyPEM);

        byte[] keyBytes = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public String generateAccessToken(String userId) {
        Map<String, String> header = new HashMap<>();
        header.put("alg", "RS256");
        header.put("typ", "JWT");

        return Jwts.builder()
                .header().add(header).and()
                .subject(userId)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + EXPIRATION_TIME_MS_ACCESS))
                .signWith(getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    public String generateRefreshToken(String userId) {

        return Jwts.builder()
                .subject(userId)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + EXPIRATION_TIME_MS_REFRESH))
                .signWith(getPrivateKey())
                .compact();
    }

    public boolean validateToken(String refreshToken, String storedRefreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            return false;
        }
        try {
            getClaims(refreshToken);
            return refreshToken.equals(storedRefreshToken);

        } catch (Exception e) {
            return false;
        }
    }

    public Jws<Claims> getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getPublicKey())
                .build()
                .parseSignedClaims(token);
    }


    public String extractUserId(String token) {
        return getClaims(token).getPayload().getSubject();
    }

    public Duration extractExpirationTime(String token) {
        return Duration.ofMillis(getClaims(token).getPayload().getExpiration().getTime());
    }

}
