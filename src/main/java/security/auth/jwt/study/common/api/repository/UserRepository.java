package security.auth.jwt.study.common.api.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.auth.jwt.study.common.api.model.User;

public interface UserRepository extends JpaRepository<User, Integer> {
    User findByUsername(String username); // JPA Query Method
}
