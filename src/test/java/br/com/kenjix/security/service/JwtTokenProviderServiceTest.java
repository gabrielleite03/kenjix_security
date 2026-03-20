package br.com.kenjix.security.service;

import br.com.kenjix.security.model.User;
import br.com.kenjix.security.repository.UserRepository;
import br.com.kenjix.security.testcontainers.AbstractTestIntegration;
import com.auth0.jwt.algorithms.Algorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(SpringExtension.class)
// Integra o Springframework com o Junit 5. Instrui o JUnit para carregar o contexto do Spring permitindo o uso de componetes,
// beans e recursos configurados no Spring no ambiente de teste. É essencial para testes que dependem do SpringContext
@DataJpaTest()
// Configura o teste para trabalhar com JPA. Carrega apenas os componentes relacionados a camada de persistência como:
// repositorios, entidades e o contexto de banco de dados. Por padrão, ele usa um banco de dados embutido como por ex.:
// H2. Neste caso, será o usado TestContainers.
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
// Por padrao o DataJPATest substitui a configuração de banco de dados por um banco por um banco de dado embutido.
// Essa annotation desativa, garantido que o banco de dados real será utilizado.
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)// Define a ordem de execução dos testes.
// É importante quando o estado de um teste depende de outro
class JwtTokenProviderServiceTest  extends AbstractTestIntegration {

    @InjectMocks
    private JwtTokenProviderService tokenProviderService;

    @Mock
    private UserService userService;

    @Mock
    private ServletUriComponentsBuilder servletUriComponentsBuilder;

    @Mock
    private UserRepository userRepository;

    @Value("${security.jwt.token.secret-key:secret}")
    private String secretKey = "secret";

    private Algorithm algorithm = null;

    @BeforeEach
    void setUp() {

        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
        algorithm = Algorithm.HMAC256(secretKey.getBytes());


        MockitoAnnotations.openMocks(this);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users/123");
        request.setContextPath("/my-app");
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));


    }

    @Test
    void createAccessToken() {
        tokenProviderService.algorithm = algorithm;
        var token = tokenProviderService.createAccessToken("koto", Arrays.asList("ADMIN", "MANAGER"));
        assertNotNull(token);
        assertTrue(token.getAuthenticated());

    }

    @Test
    void refreshToken() {
        tokenProviderService.algorithm = algorithm;
        var at = tokenProviderService.createAccessToken("koto", Arrays.asList("ADMIN", "MANAGER"));
        var token = tokenProviderService.refreshToken("Bearer " + at.getRefreshToken());
        assertNotNull(token);
        assertTrue(token.getExpiration().after(new Date()));

    }


    @Test
    void getAuthentication() {
        tokenProviderService.algorithm = algorithm;
        tokenProviderService.secretKey = secretKey;
        var at = tokenProviderService.createAccessToken("koto", Arrays.asList("ADMIN", "MANAGER"));
        User user = new User();
        user.setUserName("koto");
        when(userService.loadUserByUsername("koto")).thenReturn(user);
        var auth = tokenProviderService.getAuthentication(at.getAccessToken());
        assertNotNull(auth);
        assertEquals("koto", auth.getName());

    }

    @Test
    void resolveToken() {
        tokenProviderService.algorithm = algorithm;
        tokenProviderService.secretKey = secretKey;
        var at = tokenProviderService.createAccessToken("koto", Arrays.asList("ADMIN", "MANAGER"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users/123");
        request.addHeader("Authorization",  "Bearer "+at.getAccessToken());
        request.setContextPath("/my-app");
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        var tok = tokenProviderService.resolveToken(request);
        assertNotNull(tok);

    }

    @Test
    void resolveTokenFail() {
        tokenProviderService.algorithm = algorithm;
        tokenProviderService.secretKey = secretKey;
        var at = tokenProviderService.createAccessToken("koto", Arrays.asList("ADMIN", "MANAGER"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/users/123");
        request.addHeader("Authorization",  at.getAccessToken());
        request.setContextPath("/my-app");
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        var tok = tokenProviderService.resolveToken(request);
        assertNull(tok);

    }

    @Test
    void validateToken() {
        tokenProviderService.algorithm = algorithm;
        tokenProviderService.secretKey = secretKey;
        var at = tokenProviderService.createAccessToken("koto", Arrays.asList("ADMIN", "MANAGER"));
        var tk = tokenProviderService.validateToken(at.getAccessToken());
        assertTrue(tk);
    }


}