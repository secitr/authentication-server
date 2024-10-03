package com.example.auth_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.ldap.LdapBindAuthenticationManagerFactory;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .authorizeHttpRequests()
            .anyRequest()
            .permitAll();

    return http.build();
  }

  @Bean
  public LdapTemplate ldapTemplate() {
    return new LdapTemplate(contextSource());
  }

  @Bean
  public LdapContextSource contextSource() {
    LdapContextSource ldapContextSource = new LdapContextSource();
    ldapContextSource.setUrl("ldap://localhost:10389");
    ldapContextSource.setUserDn("uid=admin,ou=system");
    ldapContextSource.setPassword("secret");
    return ldapContextSource;
  }

  @Bean
  LdapAuthoritiesPopulator authorities(BaseLdapPathContextSource contextSource) {
    String groupSearchBase = "ou=groups,ou=system";
    DefaultLdapAuthoritiesPopulator authorities = new DefaultLdapAuthoritiesPopulator
            (contextSource, groupSearchBase);
    authorities.setGroupSearchFilter("(uniqueMember={0})");
    return authorities;
  }

  @Bean
  AuthenticationManager authManager(BaseLdapPathContextSource source, LdapAuthoritiesPopulator authorities) {
    LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(source);
    factory.setUserDnPatterns("cn={0},ou=users,ou=system");
    factory.setLdapAuthoritiesPopulator(authorities);
    return factory.createAuthenticationManager();
  }
}
