package br.com.kenjix.security;

import br.com.kenjix.security.core.Generated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@Generated
@SpringBootApplication
public class Startup {
    private static final Logger logger = LoggerFactory.getLogger(Startup.class.getName());

	public static void main(String[] args) {
        logger.info("Initializing");
		SpringApplication.run(Startup.class, args);
	}
}


