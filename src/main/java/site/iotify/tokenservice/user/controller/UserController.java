package site.iotify.tokenservice.user.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import site.iotify.tokenservice.user.dto.UserRequestDto;
import site.iotify.tokenservice.user.service.UserService;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping
    public ResponseEntity<String> registerUser(@RequestBody UserRequestDto.UserRegister userRegister) {
        System.out.println("토큰서비스에서 사용자 등록");
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.registerEmailUser(userRegister));
    }

}
