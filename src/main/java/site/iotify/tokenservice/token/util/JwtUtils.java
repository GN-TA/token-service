package site.iotify.tokenservice.token.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
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
import java.util.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtUtils {
    @Value("${token.access.valid-time}")
    private long accessTokenValidTime;
    @Value("${token.refresh.valid-time}")
    private long refreshTokenValidTime;

    @Value("${jwt.private-key}")
    private String privateKey;

    @Value("${jwt.public-key}")
    private String publicKey;

    /**
     * Token 생성을 위한 private key 객체 생성
     *
     * @return
     */
    private PrivateKey getPrivateKey() {
        String privateKeyPEM = privateKey
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

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
                .replace("-----END PUBLIC KEY-----", "")
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

    public String generateAccessToken(String email, Collection roles) {
        Map<String, String> header = new HashMap<>();
        header.put("alg", "RS256");
        header.put("typ", "JWT");

        return Jwts.builder()
                .header().add(header).and()
                .subject(email)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + accessTokenValidTime))
                .signWith(getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    public String generateRefreshToken(String userId, Collection roles) {
        Map<String, String> header = new HashMap<>();
        header.put("typ", "JWT");

        return Jwts.builder()
                .header().add(header).and()
                .subject(userId)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + refreshTokenValidTime))
                .signWith(getPrivateKey(), Jwts.SIG.RS256)
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


    public String extractEmail(String token) {
        return getClaims(token).getPayload().getSubject();
    }

    public Duration extractExpirationTime(String token) {
        return Duration.ofMillis(getClaims(token).getPayload().getExpiration().getTime());
    }

}
