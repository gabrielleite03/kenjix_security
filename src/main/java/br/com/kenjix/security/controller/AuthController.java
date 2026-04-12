package br.com.kenjix.security.controller;

import br.com.kenjix.security.data.dto.security.AccountCredentialsDTO;
import br.com.kenjix.security.data.dto.security.TokenDTO;
import br.com.kenjix.security.service.AuthService;
import io.micrometer.common.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/auth")
public class AuthController{


    public static final String INVALID_CLIENT_REQUEST = "Invalid client request!";
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private AuthService service;

    @Autowired
    public AuthController(AuthService service) {
        this.service = service;
    }

    @PostMapping("/signin")
    public ResponseEntity<TokenDTO> signin(@RequestBody AccountCredentialsDTO credentials) {
        if (credentialsIsInvalid(credentials))return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        var token = service.signIn(credentials);

        if (token == null) return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        log.info(credentials.getUsername() + " logged");
        return token;
    }

    @PutMapping("/refresh/{username}")
    public ResponseEntity<TokenDTO> refreshToken(
            @PathVariable("username") String username,
            @RequestHeader("Authorization") String refreshToken) {
        if (parametersAreInvalid(username, refreshToken))return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        var token = service.refreshToken(username, refreshToken);
        if (token == null) return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        return token;
    }

    @PutMapping("/validate")
    public ResponseEntity<Boolean> validateToken(
            @RequestHeader("Authorization") String validateToken) {
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping(value = "/createUser",
            consumes = {
                    MediaType.APPLICATION_JSON_VALUE,
                    MediaType.APPLICATION_XML_VALUE,
                    MediaType.APPLICATION_YAML_VALUE},
            produces = {
                    MediaType.APPLICATION_JSON_VALUE,
                    MediaType.APPLICATION_XML_VALUE,
                    MediaType.APPLICATION_YAML_VALUE}
    )
    public AccountCredentialsDTO create(@RequestBody AccountCredentialsDTO credentials) {
        return service.create(credentials);
    }

    private boolean parametersAreInvalid(String username, String refreshToken) {
        return StringUtils.isBlank(username) || StringUtils.isBlank(refreshToken);
    }

    private static boolean credentialsIsInvalid(AccountCredentialsDTO credentials) {
        return credentials == null ||
                StringUtils.isBlank(credentials.getPassword()) ||
                StringUtils.isBlank(credentials.getUsername());
    }
}
