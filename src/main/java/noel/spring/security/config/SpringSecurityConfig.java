package noel.spring.security.config;

import lombok.RequiredArgsConstructor;
import noel.spring.security.user.User;
import noel.spring.security.user.UserNotFoundException;
import noel.spring.security.user.UserService;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Arrays;

/**
 * Security 설정 Config
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserService userService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // basic authentication filter
        http.httpBasic().disable();

        //csrf
        http.csrf();

        // rememberMeAuthenticationFilter
        http.rememberMe();

        // authorization
        http.authorizeRequests()
                .antMatchers("/", "/home", "/signup").permitAll()// /, /home, /signup
                .antMatchers("/note").hasRole("USER") // user 권한인 경우
                .antMatchers("/admin").hasRole("ADMIN") // admin 권한인 경우
                //.antMatchers(HttpMethod.GET, "/notice").authenticated() // 인증 받은 사람만, anyREquest().authenticated()가 있기 때문에 생략 가능
                .antMatchers(HttpMethod.POST, "/notice").hasRole("ADMIN") // admin 권한이 있는 경우만 추가, 수정 가능
                .antMatchers(HttpMethod.DELETE, "/notice").hasRole("ADMIN") // admin 권한이 있는 경우만 추가, 삭제 가능
                .anyRequest().authenticated();

        // login
        http.formLogin() // formLogin 활성화
                .loginPage("/login") // 로그인 경로
                .defaultSuccessUrl("/") // 로그인 성공시
                .permitAll();

        http.logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout")) //로그아웃 경로
                .logoutSuccessUrl("/"); // 로그아웃 성공시
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
        // 정적 리소스를 다 ignore
    }

    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        return username -> {
            User user = userService.findByUsername(username);
            if (user == null) {
                throw new UsernameNotFoundException(username);
            }
            return user;
        };
    }

}
