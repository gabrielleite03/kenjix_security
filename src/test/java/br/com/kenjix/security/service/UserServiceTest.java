package br.com.kenjix.security.service;

import br.com.kenjix.security.model.User;
import br.com.kenjix.security.repository.UserRepository;
import br.com.kenjix.security.testcontainers.AbstractTestIntegration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
class UserServiceTest extends AbstractTestIntegration {

    @InjectMocks
    private UserService userService;

    @Mock
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void loadUserByUsername() {
        User user = new User();
        user.setUserName("koto");
        user.setEnabled(true);
        user.setId(123L);
        user.setFullName("Gabriel Leite");


        when(userRepository.findByUsername("koto")).thenReturn(user);
        var result = userService.loadUserByUsername("koto");
        assertNotNull(result);
        assertEquals("koto", result.getUsername());
    }

    @Test
    void loadUserByUsernameThrowsException() {
        User user = new User();
        user.setUserName("koto");
        user.setEnabled(true);
        user.setId(123L);
        user.setFullName("Gabriel Leite");


        when(userRepository.findByUsername("koto")).thenReturn(null);
        try {
           userService.loadUserByUsername("koto");
        } catch (UsernameNotFoundException e) {
            assertEquals("Username koto not found!", e.getMessage());
        }


    }
}