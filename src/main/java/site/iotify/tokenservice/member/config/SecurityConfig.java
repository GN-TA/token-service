package site.iotify.tokenservice.member.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import site.iotify.tokenservice.member.config.oauth.CustomOidcUserService;
import site.iotify.tokenservice.member.config.oauth.GoogleOAuthLoginFailureHandler;
import site.iotify.tokenservice.member.config.oauth.GoogleOAuthLoginSuccessHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final CustomOidcUserService customOidcUserService;
    private final GoogleOAuthLoginSuccessHandler googleOAuthLoginSuccessHandler;
    private final GoogleOAuthLoginFailureHandler googleOAuthLoginFailureHandler;

    public SecurityConfig(CustomOidcUserService customOidcUserService, GoogleOAuthLoginSuccessHandler googleOAuthLoginSuccessHandler, GoogleOAuthLoginFailureHandler googleOAuthLoginFailureHandler) {
        this.customOidcUserService = customOidcUserService;
        this.googleOAuthLoginSuccessHandler = googleOAuthLoginSuccessHandler;
        this.googleOAuthLoginFailureHandler = googleOAuthLoginFailureHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize ->
                        authorize.requestMatchers("/tokens/**", "/login", "/signup", "/h2-console").permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("http://localhost:8080/login")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("http://localhost:8080/?state=loginSuccess", true)
                        .failureUrl("http://localhost:8080/login?state=error")
                        .permitAll())
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("http://localhost:8080/login")
                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(customOidcUserService))
                        .authorizationEndpoint(authEndpoint -> authEndpoint.baseUri("/oauth2/authorization"))
                        .redirectionEndpoint(redirect -> redirect.baseUri("http://localhost:8090/asdf"))
                        .successHandler(googleOAuthLoginSuccessHandler)
                        .failureHandler(googleOAuthLoginFailureHandler))
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }
}
