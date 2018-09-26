package com.api.jwt.jwtpoc.rest;


import com.api.jwt.jwtpoc.model.AccessToken;
import com.api.jwt.jwtpoc.model.ApplicationUser;
import com.api.jwt.jwtpoc.repository.UserRepository;
import com.auth0.jwt.JWT;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.Lists;
import org.jasypt.util.text.BasicTextEncryptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static com.api.jwt.jwtpoc.security.SecurityConstants.*;
import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static java.nio.charset.StandardCharsets.UTF_8;

@Controller
@RequestMapping("/facebook")
public class FacebookController {

    @Value("${app.id}")
    private String APP_ID;
    @Value("${app.secret}")
    private String APP_SECRET;
    @Value("${app.base.url}")
    private String BASE_URL;
    @Value("${redirect.uri}")
    private String REDIRECT_URL;

    private final BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
    private final RestTemplate restTemplate;
    private final UserRepository userRepository;
    private BCryptPasswordEncoder encoder;

    public FacebookController(RestTemplateBuilder restTemplateBuilder, UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        restTemplate = restTemplateBuilder
                .setConnectTimeout(5000)
                .setReadTimeout(5000)
                .build();
        this.userRepository = userRepository;
        textEncryptor.setPassword("password");
        this.encoder = bCryptPasswordEncoder;
    }

    @GetMapping("/redirect")
    public RedirectView redirect() {
        String state = textEncryptor.encrypt(Instant.now().toString());
        String encodedState = Base64.getEncoder().encodeToString(state.getBytes(UTF_8));
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromHttpUrl(BASE_URL)
                .pathSegment("v3.1", "dialog", "oauth")
                .queryParam("client_id", APP_ID)
                .queryParam("redirect_uri", "http://localhost:8080/facebook")
                .queryParam("state", encodedState);
        return new RedirectView(builder.build().toUriString());
    }


    @GetMapping
    public RedirectView codeCallback(@RequestParam("code") String code,
                                     @RequestParam(value = "state") String encodedState) throws IOException {
        String uri = UriComponentsBuilder
                .fromHttpUrl("https://graph.facebook.com/v3.1/oauth/access_token")
                .queryParam("client_id", APP_ID)
                .queryParam("redirect_uri", "http://localhost:8080/facebook")
                .queryParam("client_secret", APP_SECRET)
                .queryParam("code", code).toUriString();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
        AccessToken token = restTemplate.exchange(uri, HttpMethod.GET, new HttpEntity(headers), AccessToken.class).getBody();
        String uriForGettingUserInfo = UriComponentsBuilder.fromHttpUrl("https://graph.facebook.com/v3.1/me/")
                .queryParam("access_token", token.getAccess_token())
                .toUriString();

        ObjectNode response = restTemplate.exchange(uriForGettingUserInfo, HttpMethod.GET, new HttpEntity(headers), ObjectNode.class).getBody();
        if (response.get("id") != null) {
            String id = response.get("id").textValue();
            String fullName = response.get("name").textValue();

            ApplicationUser user = userRepository.findByUsername(id);
            if (user == null) {
                user = ApplicationUser.builder().username(id).fullName(fullName)
                        .roles(Lists.newArrayList("user"))
                        .password(encoder.encode(UUID.randomUUID().toString())).build();
                userRepository.save(user);
            }

            String jwtToken = JWT.create().withSubject(user.getUsername())
                    .withArrayClaim(ROLES_CLAIM_NAME, user.getRoles().toArray(new String[user.getRoles().size()]))
                    .withClaim(FULLNAME_CLAIM_NAME, user.getFullName())
                    .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                    .sign(HMAC512(SECRET.getBytes()));
            return new RedirectView(UriComponentsBuilder.fromHttpUrl(REDIRECT_URL)
                    .queryParam("token", jwtToken)
                    .toUriString());
        }

        return new RedirectView("www.google.com");
    }
}
