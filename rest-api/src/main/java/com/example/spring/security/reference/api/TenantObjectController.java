package com.example.spring.security.reference.api;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/tenant-obj")
public class TenantObjectController {

    private final TenantObjectService tenantObjectService;

    public TenantObjectController(TenantObjectService tenantObjectService) {
        this.tenantObjectService = tenantObjectService;
    }

    @PostMapping("/documents")
    public ResponseEntity<Map<String, Object>> create(@RequestParam String content,
                                                     @AuthenticationPrincipal Jwt jwt) {
        Document document = tenantObjectService.createDocument(content, jwt);
        return ResponseEntity.ok(Map.of(
                "id", document.getId(),
                "tenant", document.getTenant(),
                "owner", document.getOwner(),
                "content", document.getContent()));
    }

    @GetMapping("/documents/{id}")
    public ResponseEntity<Map<String, Object>> get(@PathVariable Long id,
                                                   @AuthenticationPrincipal Jwt jwt) {
        Document document = tenantObjectService.getDocument(id, jwt);
        return ResponseEntity.ok(Map.of(
                "id", document.getId(),
                "tenant", document.getTenant(),
                "owner", document.getOwner(),
                "content", document.getContent()));
    }
}
