package security.auth.jwt.study.common.conf.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import security.auth.jwt.study.common.api.model.User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
 * 로그인 진행이 완료가 되면 시큐리티 session을 만들어줍니다. (Security ContextHolder)에 저장
 * Security ContextHolder 안에 Session으로 사용자 정보를 저장한다.
 * 이때 Session에 저장되는 객체는 Authentication 타입의 객체여야한다.
 * 이때 저장되는 Authentication 객체 안에는 사용자의 정보가 저장되어 있어야 한다.
 * Authentication 객체 안의 유저 정보는 UserDetails 타입의 객체이어야 한다.
 *
 * Security ContextHolder => Security Session => Authentication => UserDetails(PrincipalDetails)
 */
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user; // 컴포지션
    private Map<String,Object> attributes;

    /** 일반 로그인 */
    public PrincipalDetails(User user) {
        this.user = user;
    }

    /** OAuth 로그인 */
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    /**
     * user.getRole()이지만, 타입이 맞지 않아서 해당 타입을 형변환해서 반환한다!
     * @return 해당 유저의 권한을 리턴하는 함수
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collection;
    }

    public User getUser() {
        return user;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    /** 계정 만료여부 */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /** 계정 잠김여부 */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /** 계정 비밀번호 기간만료 여부 */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 계정 활성화 여부
     * ex) login date와 현재 시간의 차이를 구한다음 계정 로그인 시간이 지정한 시간의 범위를 넘어가면 false를 리턴한다.
     */
    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getName() {
        return getAttributes().get("sub").toString();
    }
}
