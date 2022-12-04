package security.auth.jwt.study.common.api.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import security.auth.jwt.study.common.api.model.User;
import security.auth.jwt.study.common.api.repository.UserRepository;
import security.auth.jwt.study.common.conf.auth.PrincipalDetails;

@Controller
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/")
    public String index(){
        return "index";
    }

    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        user.setRole("ROLE_USER");
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
        System.out.println("principalDetails.getAttributes() = " + principalDetails.getUser().getUsername());
        System.out.println("principalDetails.getUser().getProvider() = " + principalDetails.getUser().getProvider());
        return "사용자";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

//    @Secured("ROLE_ADMIN") // 특정 권한 접근 설정 어노테이션
//    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // 특정 권한의 접근 다중설정 어노테이션
    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager ";
    }

    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }


}
