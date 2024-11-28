package site.iotify.tokenservice.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import site.iotify.tokenservice.security.auth.JwtAuthenticationFilter;
import site.iotify.tokenservice.security.oauth.handler.GoogleOAuthLoginFailureHandler;
import site.iotify.tokenservice.security.oauth.CustomOidcUserService;
import site.iotify.tokenservice.security.oauth.handler.GoogleOAuthLoginSuccessHandler;
import site.iotify.tokenservice.token.service.TokenService;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    private final TokenService tokenService;

    private final CustomOidcUserService customOidcUserService;
    private final GoogleOAuthLoginSuccessHandler googleOAuthLoginSuccessHandler;
    private final GoogleOAuthLoginFailureHandler googleOAuthLoginFailureHandler;

    public SecurityConfig(TokenService tokenService, CustomOidcUserService customOidcUserService, GoogleOAuthLoginSuccessHandler googleOAuthLoginSuccessHandler, GoogleOAuthLoginFailureHandler googleOAuthLoginFailureHandler) {
        this.tokenService = tokenService;
        this.customOidcUserService = customOidcUserService;
        this.googleOAuthLoginSuccessHandler = googleOAuthLoginSuccessHandler;
        this.googleOAuthLoginFailureHandler = googleOAuthLoginFailureHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationConfiguration authenticationConfiguration) throws Exception {
        http
                .authorizeHttpRequests(authorize ->
                        authorize.requestMatchers("/login", "/refresh", "/logout").permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(form -> form
                                .disable()
//                        .loginPage("http://localhost:8080/login")
//                        .loginProcessingUrl("/login")
//                        .defaultSuccessUrl("http://localhost:8080/?state=loginSuccess", true)
//                        .failureUrl("http://localhost:8080/login?state=error")
//                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("http://localhost:8080/login")
                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(customOidcUserService))
                        .authorizationEndpoint(authEndpoint -> authEndpoint.baseUri("/oauth2/authorization"))
                        .redirectionEndpoint(redirect -> redirect.baseUri("http://localhost:8091/login"))
                        .successHandler(googleOAuthLoginSuccessHandler)
                        .failureHandler(googleOAuthLoginFailureHandler))
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable);

        JwtAuthenticationFilter loginFilter = new JwtAuthenticationFilter(authenticationManager(authenticationConfiguration), tokenService);
        loginFilter.setFilterProcessesUrl("/login");
        http
                .addFilterAt(
                loginFilter,
                UsernamePasswordAuthenticationFilter.class
        )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .addLogoutHandler(new JwtLogoutHandler(tokenService))
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            response.setStatus(HttpStatus.CREATED.value());
                            response.getWriter().write("logout successful");
                        })
                )
        ;

        return http.build();
    }
}
