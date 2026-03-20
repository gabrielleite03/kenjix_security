package br.com.kenjix.security.unit.controller;

import br.com.kenjix.security.controller.AuthController;
import br.com.kenjix.security.data.dto.security.AccountCredentialsDTO;
import br.com.kenjix.security.data.dto.security.TokenDTO;
import br.com.kenjix.security.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @InjectMocks
    private AuthController authController;

    @Mock
    private AuthService authService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void signin() {
        AccountCredentialsDTO credentialsDTO = new AccountCredentialsDTO();
        credentialsDTO.setUsername("koto");
        credentialsDTO.setPassword("123");

        TokenDTO tokenDTO = new TokenDTO();
        tokenDTO.setAccessToken("ABC");

        when(authService.signIn(credentialsDTO)).thenReturn(ResponseEntity.ok(tokenDTO));

        ResponseEntity<?> result = authController.signin(credentialsDTO);

        assertNotNull(result);
        assertEquals(HttpStatus.OK, result.getStatusCode());

    }

    @Test
    void signinFail() {
        AccountCredentialsDTO credentialsDTO = new AccountCredentialsDTO();
        credentialsDTO.setUsername("koto");
        credentialsDTO.setPassword("123");

        TokenDTO tokenDTO = new TokenDTO();
        tokenDTO.setAccessToken("ABC");
        when(authService.signIn(credentialsDTO)).thenReturn(null);

        ResponseEntity<TokenDTO> result = authController.signin(credentialsDTO);

        assertNotNull(result);

    }
    @Test
    void signinCredentialsFail() {
        AccountCredentialsDTO credentialsDTO = new AccountCredentialsDTO();
        credentialsDTO.setUsername("");
        credentialsDTO.setPassword("123");

        TokenDTO tokenDTO = new TokenDTO();
        tokenDTO.setAccessToken("ABC");

        ResponseEntity<?> result = authController.signin(credentialsDTO);
        assertNotNull(result);
        assertEquals(HttpStatus.FORBIDDEN, result.getStatusCode());
    }

    @Test
    void signinCredentialsPasswordFail() {
        AccountCredentialsDTO credentialsDTO = new AccountCredentialsDTO();
        credentialsDTO.setUsername("koto");
        credentialsDTO.setPassword("");

        TokenDTO tokenDTO = new TokenDTO();
        tokenDTO.setAccessToken("ABC");

        ResponseEntity<?> result = authController.signin(credentialsDTO);
        assertNotNull(result);
        assertEquals(HttpStatus.FORBIDDEN, result.getStatusCode());
    }

    @Test
    void signinCredentialsNullFail() {

        ResponseEntity<?> result = authController.signin(null);
        assertNotNull(result);
        assertEquals(HttpStatus.FORBIDDEN, result.getStatusCode());
    }

    @Test
    void refreshToken() {


        when(authService.refreshToken("koto", "123")).thenReturn(ResponseEntity.ok(new TokenDTO()));
        ResponseEntity<?> result = authController.refreshToken("koto", "123");

        assertNotNull(result);
        assertEquals(HttpStatus.OK, result.getStatusCode());
    }

    @Test
    void refreshTokenFail() {


        when(authService.refreshToken("koto", "123")).thenReturn(null);
        ResponseEntity<TokenDTO> result = authController.refreshToken("koto", "123");

        assertNotNull(result);
    }

    @Test
    void refreshTokenParamUserNameInvalid() {
        ResponseEntity<?> result = authController.refreshToken("", "123");

        assertNotNull(result);
        assertEquals(HttpStatus.FORBIDDEN, result.getStatusCode());
    }

    @Test
    void refreshTokenParamRefreshTokenInvalid() {
        ResponseEntity<?> result = authController.refreshToken("koto", "");

        assertNotNull(result);
        assertEquals(HttpStatus.FORBIDDEN, result.getStatusCode());
    }

    @Test
    void refreshTokenParamNull() {
        ResponseEntity<?> result = authController.refreshToken(null, "123");

        assertNotNull(result);
        assertEquals(HttpStatus.FORBIDDEN, result.getStatusCode());
    }

    @Test
    void create() {
        AccountCredentialsDTO credentialsDTO = new AccountCredentialsDTO();
        credentialsDTO.setUsername("koto");
        credentialsDTO.setPassword("123");

        when(authService.create(credentialsDTO)).thenReturn(new AccountCredentialsDTO());
        AccountCredentialsDTO result = authController.create(credentialsDTO);

        assertNotNull(result);
    }
}