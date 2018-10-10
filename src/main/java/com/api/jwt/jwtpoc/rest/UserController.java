package com.api.jwt.jwtpoc.rest;

import com.api.jwt.jwtpoc.model.ApplicationUser;
import com.api.jwt.jwtpoc.repository.UserRepository;
import com.google.common.collect.Lists;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserRepository userRepository;
    private BCryptPasswordEncoder encoder;

    public UserController(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.encoder = bCryptPasswordEncoder;
    }

    @PostMapping("/sign-up")
    public void signUp(@RequestBody ApplicationUser user) {
        if (userRepository.findByUsername(user.getUsername()) == null) {
            user.setPassword(encoder.encode(user.getPassword()));
            user.setRoles(Lists.newArrayList("user", "admin"));
            userRepository.save(user);
        }
    }

    @PostConstruct
    public void addSomeUsers() {
        IntStream.range(0, 100).forEach(i -> {
                    if (userRepository.findByUsername("wolf-" + i) == null) {
                        userRepository.save(ApplicationUser.builder()
                                .fullName("Wolfgang " + i)
                                .password(encoder.encode("pass"))
                                .username("wolf-" + i)
                                .build());
                    }
                }

        );
    }


    @GetMapping
    @PreAuthorize("hasAnyRole('admin')")
    public List<ApplicationUser> getAllUsers() {
        return userRepository.findAll().stream().peek(t -> t.setPassword("")).collect(Collectors.toList());
    }

    @GetMapping("/is-valid")
    @PreAuthorize("hasAnyRole('user')")
    public boolean isAuthenticated() {
        return true;
    }


    @PostMapping("{username}/roles")
    @PreAuthorize("hasAnyRole('admin')")
    public List<String> updateRoles(@PathVariable("username") String username, @RequestBody List<String> roles) {
        ApplicationUser user = userRepository.findByUsername(username);
        user.setRoles(roles);
        userRepository.save(user);
        return roles;
    }

    @DeleteMapping
    @PreAuthorize("hasAnyRole('admin')")
    public List<ApplicationUser> deleteUsers(@RequestBody List<String> usernames) {
        List<ApplicationUser> deletedUsers = usernames.stream()
                .map(userRepository::findByUsername)
                .collect(Collectors.toList());
        deletedUsers.forEach(userRepository::delete);
        return deletedUsers;
    }

    @GetMapping("self")
    @PreAuthorize("isAuthenticated()")
    public ApplicationUser getDetailsAboutLoggedInUser() {
        return userRepository.findByUsername(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    }

    @PostMapping("self/full-name")
    @PreAuthorize("isAuthenticated()")
    public ApplicationUser updateFullname(@RequestBody String fullname) {
        ApplicationUser user =  userRepository.findByUsername(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
        user.setFullName(fullname);
        userRepository.save(user);
        return user;
    }

}
