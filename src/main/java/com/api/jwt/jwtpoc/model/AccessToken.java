package com.api.jwt.jwtpoc.model;


import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class AccessToken {

    private String access_token;
    private String token_type;
    private long expires_in;
}
