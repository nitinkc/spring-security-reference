package com.example.spring.security.reference.ldapauth;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
        logger.info("🔍 [LDAP-MAPPER] Mapping LDAP user: {}", username);
        String cn = ctx.getStringAttribute("cn");
        String mail = ctx.getStringAttribute("mail");
        logger.debug("📚 [LEARNING] Extracted attributes: cn={}, mail={}", cn, mail);

        Set<GrantedAuthority> mappedAuthorities = new HashSet<>(authorities);
        // Example: Add custom authority if user is in a special group
        if ("specialuser".equals(username)) {
            mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_SPECIAL"));
            logger.debug("⭐ [LDAP-MAPPER] Added ROLE_SPECIAL for user: {}", username);
        }

        LdapUserDetailsImpl.Essence essence = new LdapUserDetailsImpl.Essence();
        essence.setUsername(username);
        essence.setAuthorities(mappedAuthorities);
        essence.setDn(ctx.getDn().toString());
        return essence.createUserDetails();
    }

    @Override
    public void mapUserToContext(UserDetails user, DirContextOperations ctx) {
        // Not used in this demo
    }
}

        logger.debug("📚 [LEARNING] This mapper converts LDAP user data to Spring Security UserDetails");import java.util.Set;

    }

/**

    @Override * Custom LDAP User Details Context Mapper.

    public UserDetails mapUserFromContext(DirContextOperations ctx, String username,  * 

                                         Collection<? extends GrantedAuthority> authorities) { * This mapper demonstrates how to:

        logger.info("🔄 [LDAP-MAPPER] Mapping LDAP user to UserDetails: {}", username); * - Extract additional user information from LDAP

        logger.debug("📚 [LEARNING] Converting LDAP directory entry to Spring Security user"); * - Map LDAP attributes to Spring Security UserDetails

 * - Add custom authorities based on LDAP attributes

        // Extract LDAP attributes * - Handle LDAP-specific user context mapping

        String commonName = ctx.getStringAttribute("cn"); */

        String email = ctx.getStringAttribute("mail");public class PersonContextMapper implements UserDetailsContextMapper {

        String displayName = ctx.getStringAttribute("displayName");

            @Override

        logger.debug("📋 [LDAP-MAPPER] Extracted LDAP attributes:");    public UserDetails mapUserFromContext(DirContextOperations ctx, String username, 

        logger.debug("   • Common Name (cn): {}", commonName);                                        Collection<? extends GrantedAuthority> authorities) {

        logger.debug("   • Email (mail): {}", email);        

        logger.debug("   • Display Name: {}", displayName);        // Extract additional attributes from LDAP

                String fullName = ctx.getStringAttribute("cn");

        // Log authorities granted from LDAP groups        String email = ctx.getStringAttribute("mail");

        logger.debug("👥 [LDAP-MAPPER] Authorities from LDAP groups:");        

        authorities.forEach(auth ->         // Add custom authorities based on LDAP attributes

            logger.debug("   • Authority: {}", auth.getAuthority())        Set<GrantedAuthority> mappedAuthorities = new HashSet<>(authorities);

        );        

                // Example: Add admin role if user is in special LDAP group

        // Add additional authorities based on LDAP attributes or business rules        String[] memberOf = ctx.getStringAttributes("memberOf");

        Set<GrantedAuthority> allAuthorities = new HashSet<>(authorities);        if (memberOf != null) {

                    for (String group : memberOf) {

        // Example: Add special authority for admin users                if (group.contains("administrators")) {

        if ("admin".equalsIgnoreCase(username) ||                     mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));

            (email != null && email.contains("admin"))) {                }

            allAuthorities.add(new SimpleGrantedAuthority("ROLE_LDAP_ADMIN"));            }

            logger.debug("⭐ [LDAP-MAPPER] Added ROLE_LDAP_ADMIN for admin user");        }

        }

                // Create enhanced user details with LDAP information

        // Create UserDetails with LDAP attributes        LdapUserDetailsImpl.Essence essence = new LdapUserDetailsImpl.Essence(ctx);

        LdapUserDetailsImpl.Essence essence = new LdapUserDetailsImpl.Essence();        essence.setUsername(username);

        essence.setUsername(username);        essence.setAuthorities(mappedAuthorities);

        essence.setAuthorities(allAuthorities);        

        essence.setEnabled(true);        return essence.createUserDetails();

        essence.setAccountNonExpired(true);    }

        essence.setCredentialsNonExpired(true);

        essence.setAccountNonLocked(true);    @Override

            public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {

        UserDetails userDetails = essence.createUserDetails();        // This method is used when updating user information back to LDAP

                // For read-only LDAP authentication, this can remain empty

        logger.info("✅ [LDAP-MAPPER] Successfully mapped LDAP user: {} with {} authorities",         throw new UnsupportedOperationException("PersonContextMapper only supports reading from LDAP");

                   username, allAuthorities.size());    }

        logger.debug("🔄 [LEARNING] UserDetails created with LDAP attributes and computed authorities");}
        
        return userDetails;
    }

    @Override
    public void mapUserToContext(UserDetails user, DirContextOperations ctx) {
        logger.debug("📤 [LDAP-MAPPER] Mapping UserDetails back to LDAP context (rarely used)");
        logger.debug("📚 [LEARNING] This method is used for LDAP write operations");
        
        // This method is typically used when writing user data back to LDAP
        // Not commonly needed for authentication-only scenarios
        logger.debug("⚠️ [LDAP-MAPPER] User-to-context mapping not implemented (read-only LDAP)");
    }
}