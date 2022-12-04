package security.auth.jwt.study.common.conf;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import security.auth.jwt.study.common.api.service.PrincipalDetailsService;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true) // @Secured 어노테이션 활성화, @PreAuthorize 메소드 활성화
public class SecurityConfig {

    @Autowired
    private PrincipalDetailsService principalDetailsService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user").authenticated()
                .antMatchers("/manager").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalDetailsService);
        // /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행한다.
        // controller에 /login을 만들지 않아도 된다.
        return http.build();
    }

}
