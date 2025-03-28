package site.iotify.tokenservice.security;

import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import site.iotify.tokenservice.token.filter.JwtAuthenticationFilter;
import site.iotify.tokenservice.security.oauth.handler.GoogleOAuthLoginFailureHandler;
import site.iotify.tokenservice.security.oauth.CustomOidcUserService;
import site.iotify.tokenservice.security.oauth.handler.GoogleOAuthLoginSuccessHandler;
import site.iotify.tokenservice.token.handler.JwtLogoutHandler;
import site.iotify.tokenservice.token.service.TokenService;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    private final static String PATH_PREFIX = "/v1";
    private final static String[] allowedUrls = {
            PATH_PREFIX + "/login",
            PATH_PREFIX + "/refresh",
            PATH_PREFIX + "/logout"
    };

    @Value("${service.front-url}")
    private String frontUrl;

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
    CorsConfigurationSource corsConfigurationSource() {
        return request -> {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedHeaders(Collections.singletonList("*"));
            config.setAllowedMethods(Collections.singletonList("*"));
            config.setAllowedOriginPatterns(Collections.singletonList("*"));
            config.setAllowCredentials(true);
            return config;
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationConfiguration authenticationConfiguration) throws Exception {
        http
                .authorizeHttpRequests(authorize ->
                        authorize.requestMatchers(allowedUrls).permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(AbstractHttpConfigurer::disable
                )
                // TODO : front로 처리하면 될 것 같은데 좀 더 알아봐야 할 것 같음
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("http://" + frontUrl + "/login")
                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(customOidcUserService))
                        .authorizationEndpoint(authEndpoint -> authEndpoint.baseUri("/oauth2/authorization"))
                        .redirectionEndpoint(redirect -> redirect.baseUri("http://localhost:8091" + allowedUrls[0]))
                        .successHandler(googleOAuthLoginSuccessHandler)
                        .failureHandler(googleOAuthLoginFailureHandler))
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable);

        JwtAuthenticationFilter loginFilter = new JwtAuthenticationFilter(authenticationManager(authenticationConfiguration), tokenService);
        loginFilter.setFilterProcessesUrl(allowedUrls[0]);
        http
                .addFilterAt(
                        loginFilter,
                        UsernamePasswordAuthenticationFilter.class
                )
                .logout(logout -> logout
                        .logoutUrl(allowedUrls[2])
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
