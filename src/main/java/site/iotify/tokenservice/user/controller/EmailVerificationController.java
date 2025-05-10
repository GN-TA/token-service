package site.iotify.tokenservice.user.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import site.iotify.tokenservice.user.service.DoorayService;
import site.iotify.tokenservice.user.service.EmailVerificationService;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/email")
@Slf4j
public class EmailVerificationController {

    private final EmailVerificationService emailVerificationService;
    private final DoorayService doorayService;


    @PostMapping("/verify")
    public ResponseEntity<Void> sendVerificationEmail(@RequestBody Map<String, String> requestMap) {
        log.info("Email verification request received: {}", requestMap);
        emailVerificationService.sendVerificationEmail(requestMap.get("email"));
        return ResponseEntity.ok().build();
    }

    @PostMapping("/verify-code")
    public ResponseEntity<?> verifyCode(@RequestParam("type") String type,
                                        @RequestBody Map<String, String> request) {
        String email = request.get("email");
        String code = request.get("code");
        log.info("Verification code check request received: email={}, code={}", email, code);
        boolean isVerified = false;
        if ("email".equals(type)) {
            isVerified = emailVerificationService.verifyCode(email, code);
        } else if ("social".equals(type)) {
            isVerified = emailVerificationService.verifyCode4SocialSignup(email, code);
        }
        if (isVerified) {
            log.info("Email verification success");
            return ResponseEntity.ok().build();
        } else {
            log.warn("Email verification failed");
            return ResponseEntity.badRequest().body("Invalid verification code");
        }
    }

    @PostMapping("/nhn")
    public ResponseEntity<Void> verifyNHNEmail(@RequestBody Map<String, String> requestMap) {
        doorayService.isNHNMember(requestMap.get("email"));
        return ResponseEntity.ok().build();
    }
}
