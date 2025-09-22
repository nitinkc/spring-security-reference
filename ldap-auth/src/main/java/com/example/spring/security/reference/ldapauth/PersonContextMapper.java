package com.example.spring.security.reference.ldapauth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Custom LDAP User Details Context Mapper.
 * Educational Logging: Shows how to map LDAP attributes to Spring Security UserDetails.
 */
public class PersonContextMapper implements UserDetailsContextMapper {
    private static final Logger logger = LogManager.getLogger(PersonContextMapper.class);

    public PersonContextMapper() {
        logger.info("👤 [LDAP-MAPPER] Initializing LDAP Person Context Mapper");
    }

  @Override
  public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {
    return null;
  }

  @Override
  public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {

  }
}