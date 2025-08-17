// SignatureService.java
package com.example.xadessigner.service;

public interface SignatureService {
    String signXmlWithXadesEpes(String xmlContent, String password) throws Exception;
}