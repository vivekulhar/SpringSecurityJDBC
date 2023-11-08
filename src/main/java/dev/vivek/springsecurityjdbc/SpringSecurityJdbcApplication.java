package dev.vivek.springsecurityjdbc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class SpringSecurityJdbcApplication {

    public static void main(String[] args) {

        SpringApplication.run(SpringSecurityJdbcApplication.class, args);

    }

}
