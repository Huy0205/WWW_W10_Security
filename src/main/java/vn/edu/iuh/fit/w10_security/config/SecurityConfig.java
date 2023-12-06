package vn.edu.iuh.fit.w10_security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private DataSource dataSource;

//    @Autowired
//    public void globalConfig(AuthenticationManagerBuilder authenticationManagerBuilder, PasswordEncoder encoder) throws Exception {
//        authenticationManagerBuilder.inMemoryAuthentication()
//                .withUser(User.withUsername("admin")
//                .password(encoder.encode("admin"))
//                        .roles("ADMIN")
//                        .build())
//                .withUser(User.withUsername("teo")
//                        .password(encoder.encode("teo"))
//                        .roles("TEO")
//                        .build())
//                .withUser(User.withUsername("ty")
//                        .password(encoder.encode("ty"))
//                        .roles("USER")
//                        .build());
//    }

    @Autowired
    public void globalConfig(AuthenticationManagerBuilder authenticationManagerBuilder, PasswordEncoder encoder) throws Exception {
        authenticationManagerBuilder.jdbcAuthentication()
                .dataSource(dataSource)
                .withDefaultSchema()
                .withUser(User.withUsername("admin")
                        .password(encoder.encode("admin"))
                        .roles("ADMIN")
                        .build())
                .withUser(User.withUsername("teo")
                        .password(encoder.encode("teo"))
                        .roles("TEO")
                        .build())
                .withUser(User.withUsername("ty")
                        .password(encoder.encode("ty"))
                        .roles("USER")
                        .build());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests((auth->auth
                .requestMatchers("/", "/home", "/index").permitAll()
                .requestMatchers("/api/**").hasAnyRole("ADMIN", "TEO", "USER")
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll()
        ));
        httpSecurity.csrf(csrf->csrf.ignoringRequestMatchers("/h2-console/**"));
        httpSecurity.headers(headers->headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        httpSecurity.httpBasic(Customizer.withDefaults());
        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
