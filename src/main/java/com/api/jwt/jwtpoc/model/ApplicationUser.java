package com.api.jwt.jwtpoc.model;


import lombok.*;

import javax.persistence.*;
import java.util.List;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ApplicationUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String username;
    private String fullName;
    @ElementCollection(fetch = FetchType.EAGER)
    private List<String> roles;
    private String password;
}
