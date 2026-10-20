package ru.learning.security;

import java.util.List;
import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {
    @GetMapping("/api/hello")
    public Map<String, String> hello(Authentication authentication) {
        return Map.of(
                "message", "Вы вошли в защищённую часть приложения.",
                "username", authentication.getName());
    }

    @GetMapping("/api/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> admin(Authentication authentication) {
        return Map.of(
                "message", "Доступ разрешён: это административный раздел.",
                "username", authentication.getName());
    }

    @GetMapping("/api/me")
    public Map<String, Object> me(Authentication authentication) {
        List<String> roles = authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority().replaceFirst("^ROLE_", ""))
                .toList();
        return Map.of("username", authentication.getName(), "roles", roles);
    }
}
