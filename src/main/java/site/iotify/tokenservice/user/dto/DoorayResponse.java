package site.iotify.tokenservice.user.dto;

import lombok.Getter;
import lombok.ToString;

@Getter
public class DoorayResponse {

    @Getter
    @ToString
    public static class DoorayMemberResponse {
        private Header header;
        private Result[] result;
        private Integer totalCount;
    }

    @Getter
    @ToString
    public static class Header {
        private Long resultCode;
        private String resultMessage;
        private Boolean isSuccessful;
    }

    @Getter
    @ToString
    public static class Result {
        private String id;
        private String userCode;
        private String name;
        private String externalEmailAddress;
    }
}
