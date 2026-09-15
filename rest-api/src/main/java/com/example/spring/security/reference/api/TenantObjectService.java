package com.example.spring.security.reference.api;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
public class TenantObjectService {

    private final DocumentRepository documentRepository;

    public TenantObjectService(DocumentRepository documentRepository) {
        this.documentRepository = documentRepository;
    }

    public Document createDocument(String content, Jwt jwt) {
        String tenant = jwt.getClaimAsString("tenant");
        String owner = jwt.getSubject();
        Document document = new Document(tenant, owner, content);
        return documentRepository.save(document);
    }

    public Document getDocument(Long id, Jwt jwt) {
        Document document = documentRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Document not found"));

        String tokenTenant = jwt.getClaimAsString("tenant");
        if (!tokenTenant.equals(document.getTenant())) {
            throw new AccessDeniedException("Cross-tenant access denied");
        }

        String subject = jwt.getSubject();
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) jwt.getClaim("roles");
        if (subject.equals(document.getOwner()) || (roles != null && roles.contains("ADMIN"))) {
            return document;
        }

        throw new AccessDeniedException("Object access denied");
    }
}
