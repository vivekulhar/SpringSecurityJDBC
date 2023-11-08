package dev.vivek.springsecurityjdbc.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.ldap.EmbeddedLdapServerContextSourceFactoryBean;
import org.springframework.security.config.ldap.LdapBindAuthenticationManagerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.userdetails.PersonContextMapper;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private DataSource dataSource;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    /*
     * This is required to enable the authentication manager bean
     * */

    @Bean
    public UserDetailsManager users() {
        /*UserDetails user = User.builder()
                .username("user")
                .password(bCryptPasswordEncoder.encode("user"))
                .roles("USER")
                .build();*/
        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);

        users.setUsersByUsernameQuery("select user_name, user_pwd, user_enabled from user where user_name=?");
        users.setAuthoritiesByUsernameQuery("select user_name, user_role from user where user_name=?");
        users.setEnableAuthorities(true);
        //users.createUser(user);
        return users;
    }

    /*
     * This is required to enable the authorization manager bean
     * */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/home").permitAll()
                        .requestMatchers("/welcome").authenticated()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/emp").hasRole("EMPLOYEE")
                        .requestMatchers("/mgr").hasRole("MANAGER")
                        .requestMatchers("/common").hasAnyRole("ADMIN", "EMPLOYEE", "MANAGER")
                        .anyRequest().authenticated())
                .formLogin(formLogin->formLogin.defaultSuccessUrl("/welcome", true))
                .logout(logout->logout.logoutSuccessUrl("/logout"))
                .exceptionHandling(exceptionHandling->exceptionHandling.accessDeniedPage("/accessDenied"));


        return http.build();
    }
}