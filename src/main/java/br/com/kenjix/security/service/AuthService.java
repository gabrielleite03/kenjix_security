package br.com.kenjix.security.service;

import br.com.kenjix.security.data.dto.security.AccountCredentialsDTO;
import br.com.kenjix.security.data.dto.security.TokenDTO;
import br.com.kenjix.security.exception.InvalidJwtAuthenticationException;
import br.com.kenjix.security.exception.RequiredObjectIsNullException;
import br.com.kenjix.security.model.User;
import br.com.kenjix.security.repository.UserRepository;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;



@Service
public class AuthService {

    @Value("${security.jwt.token.secret-key}")
    private String secretKey;
    private Algorithm algorithm;

    @Autowired
    public AuthService(AuthenticationManager authenticationManager, JwtTokenProviderService tokenProvider, UserRepository repository) {
        this.authenticationManager = authenticationManager;
        this.tokenProvider = tokenProvider;
        this.repository = repository;
    }

    @PostConstruct
    public void init() {
        System.out.println("JWT SECRET: " + secretKey);
    }


    Logger logger = LoggerFactory.getLogger(AuthService.class);


    private final AuthenticationManager authenticationManager;


    private final JwtTokenProviderService tokenProvider;


    private final UserRepository repository;

    public ResponseEntity<TokenDTO> signIn(AccountCredentialsDTO credentials) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        credentials.getUsername(),
                        credentials.getPassword()
                )
        );

        var user = repository.findByUsername(credentials.getUsername());
        if (user == null) {
            TokenDTO token = new TokenDTO();
            token.setAuthenticated(false);
            return new ResponseEntity<>(token, HttpStatus.FORBIDDEN);
        }

        var token = tokenProvider.createAccessToken(
                credentials.getUsername(),
                user.getRoles()
        );
        return ResponseEntity.ok(token);
    }

    public ResponseEntity<TokenDTO> refreshToken(String username, String refreshToken) {
        var user = repository.findByUsername(username);
        TokenDTO token;
        if (user != null) {
            token = tokenProvider.refreshToken(refreshToken);
        } else {
            token = new TokenDTO();
            token.setAuthenticated(false);
            return new ResponseEntity<>(token, HttpStatus.FORBIDDEN);
        }
        return ResponseEntity.ok(token);
    }

    public boolean validateToken(String token){
        try {
            DecodedJWT decodedJWT = decodedToken(token);
            return !decodedJWT.getExpiresAt().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    private DecodedJWT decodedToken(String token) {
        try {
            JWTVerifier verifier = JWT.require(getAlgorithm())
                    .build();

            return verifier.verify(token);

        } catch (Exception e) {
            throw new InvalidJwtAuthenticationException("Expired or Invalid JWT Token!");
        }
    }



    private Algorithm getAlgorithm() {
        if (algorithm == null) {
            String encoded = Base64.getEncoder().encodeToString(secretKey.getBytes());
            algorithm = Algorithm.HMAC256(encoded.getBytes());
        }
        return algorithm;
    }



    public AccountCredentialsDTO create(AccountCredentialsDTO user) {

        if (user == null) throw new RequiredObjectIsNullException();

        logger.info("Creating one new User!");
        var entity = new User();
        entity.setFullName(user.getFullname());
        entity.setUserName(user.getUsername());
        entity.setPassword(generateHashedPassword(user.getPassword()));
        entity.setAccountNonExpired(true);
        entity.setAccountNonLocked(true);
        entity.setCredentialsNonExpired(true);
        entity.setEnabled(true);

        var dto = repository.save(entity);
        return new AccountCredentialsDTO(dto.getUsername(), dto.getPassword(), dto.getFullName());
    }

    private String generateHashedPassword(String password) {

        PasswordEncoder pbkdf2Encoder = new Pbkdf2PasswordEncoder(
                "", 8, 185000,
                Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256);

        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("pbkdf2", pbkdf2Encoder);
        DelegatingPasswordEncoder passwordEncoder = new DelegatingPasswordEncoder("pbkdf2", encoders);

        passwordEncoder.setDefaultPasswordEncoderForMatches(pbkdf2Encoder);
        return passwordEncoder.encode(password);
    }
}