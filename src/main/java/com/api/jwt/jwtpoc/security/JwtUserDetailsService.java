package com.api.jwt.jwtpoc.security;

import com.api.jwt.jwtpoc.model.ApplicationUser;
import com.api.jwt.jwtpoc.repository.UserRepository;
import com.google.common.collect.Lists;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public JwtUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        ApplicationUser applicationUser = userRepository.findByUsername(s);
        return new User(applicationUser.getUsername(), applicationUser.getPassword(), fromListOfRoles(applicationUser.getRoles()));
    }

    public static Collection<GrantedAuthority> fromListOfRoles(List<String> roles) {
        if (roles == null) {
         return Collections.emptyList();
        }
        return roles.stream().map(t -> (GrantedAuthority) () -> t).collect(Collectors.toList());
    }
}
