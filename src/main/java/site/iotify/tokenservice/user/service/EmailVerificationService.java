package site.iotify.tokenservice.user.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import site.iotify.tokenservice.token.dao.RedisDao;
import site.iotify.tokenservice.user.exception.UnauthenticatedException;

import java.time.Duration;
import java.util.Random;

@Slf4j
@Service
public class EmailVerificationService {
    private final JavaMailSender mailSender;
    private final RedisDao redisDao;

    public EmailVerificationService(JavaMailSender mailSender, RedisDao redisDao) {
        this.mailSender = mailSender;
        this.redisDao = redisDao;
    }


    public boolean isEmailVerified(String email) {
        String emailToken = redisDao.getToken(email);
        if (emailToken == null) {
            return false;
        }
        return true;
    }

    public void sendVerificationEmail(String email) {
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, false, "UTF-8");
            helper.setTo(email);
            helper.setSubject("이메일 인증 코드");
            helper.setText(buildEmailContent(generateVerificationCode(email)), true);

            mailSender.send(mimeMessage);
            log.info("Email sent to {}", email);
        } catch (MessagingException e) {
            log.error("Failed to send email to {}: {}", email, e.getMessage());
            throw new RuntimeException("Failed to send email", e);
        }
    }

    private String buildEmailContent(String code) {
        return "<h1>이메일 인증 코드</h1>" +
                "<p>아래 코드를 회원가입 화면에 입력하세요:</p>" +
                "<h2 style='color: blue;'>" + code + "</h2>";
    }

    public String generateVerificationCode(String email) {
        String code = String.valueOf(new Random().nextInt(900000) + 100000);
        redisDao.saveToken(email, code, Duration.ofMillis(1000L * 60 * 5));
        return code;
    }

    public boolean verifyCode(String email, String code) {
        return code.equals(redisDao.getToken(email));
    }

    public boolean verifyCode4SocialSignup(String email, String code) {
        if (verifyCode(email, code)) {
            redisDao.saveToken(email, "true", Duration.ofMinutes(5L));
            return true;
        } else {
            throw new UnauthenticatedException("인증번호가 올바르지 않습니다");
        }
    }
}
