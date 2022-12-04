package security.auth.jwt.study.common.api.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import security.auth.jwt.study.common.api.model.User;
import security.auth.jwt.study.common.api.repository.UserRepository;
import security.auth.jwt.study.common.conf.auth.PrincipalDetails;

import java.util.UUID;

/**
 * 시큐리티 설정에서 loginProcessingUrl("/login");
 * /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC 되어있는 loadUserByUsername 함수가 호출된다.
 *
 */
@Service
public class PrincipalDetailsService extends DefaultOAuth2UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration()); // registration 으로 provider(공급자) 정보를 알 수 있음
        System.out.println("userRequest.getAccessToken() = " + userRequest.getAccessToken());

        /**
         * 구글 로그인 버튼 클릭 시 => 구글 로인창 => 로그인 완료 => code를 리턴(OAuth-Client라이브러리) -> AccessToken요청
         * UserRequest 정보 -> loadUser함수출력 -> Provider로부터 회원프로필 Get
         */
        System.out.println("super.loadUser(userRequest).getAttributes() = " + super.loadUser(userRequest).getAttributes());

        OAuth2User oauthUser = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getClientId(); // google
        String providerId = oauthUser.getAttribute("sub");
        String email = oauthUser.getAttribute("email");
        String username = provider.concat("_").concat(providerId);
        String password = bCryptPasswordEncoder.encode(username);
        String role = "ROLE_USER";

        User user = userRepository.findByUsername(username);
        if ( user == null  ){
            user = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId).build();
            userRepository.save(user);
        }

        return new PrincipalDetails(user,oauthUser.getAttributes());
    }

    /**
     * 해당 함수에서 UserDetails 객체가 리턴되면 Authentication 객체안에 값이 바인딩된다.
     * 결과적으로 Security ContextHolder 안에 Security Session (Authentication(userDetails))가 들어가게 된다.
     * @param username the username identifying the user whose data is required.
     * @return Authentication(userDetails)
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        if ( userEntity != null ) {
            return new PrincipalDetails(userEntity);
        }
        return null;
    }

}
