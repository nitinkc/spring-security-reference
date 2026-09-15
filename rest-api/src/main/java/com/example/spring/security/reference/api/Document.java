package com.example.spring.security.reference.api;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class Document {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String tenant;
    private String owner;
    private String content;

    public Document() {
    }

    public Document(String tenant, String owner, String content) {
        this.tenant = tenant;
        this.owner = owner;
        this.content = content;
    }

    public Long getId() {
        return id;
    }

    public String getTenant() {
        return tenant;
    }

    public String getOwner() {
        return owner;
    }

    public String getContent() {
        return content;
    }
}
