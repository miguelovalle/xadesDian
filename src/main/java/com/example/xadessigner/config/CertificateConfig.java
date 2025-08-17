package com.example.xadessigner.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "certificate")
public class CertificateConfig {
    private String path;
    private String password;
    private String alias;

    // Getters y Setters
    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }
    
    @Override
    public String toString() {
        return "CertificateConfig{" +
                "path='" + path + '\'' +
                ", password='****'" +  // No mostrar la contraseña
                ", alias='" + alias + '\'' +
                '}';
    }
}