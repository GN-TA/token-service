package site.iotify.tokenservice.user.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
public class UserRequestDto {

    @Getter
    @ToString
    @Builder
    @Setter
    public static class UserRegister {
        private String name;
        private String email;
        private String emailCode;
        private String nhnEmail;
        private String nhnEmailCode;
        private String password;
        private String passwordConfirmation;
        private String provider;
    }

}
