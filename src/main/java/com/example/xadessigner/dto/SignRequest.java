package com.example.xadessigner.dto;

public class SignRequest {
    private String xmlContent;

    public SignRequest() {}

    public SignRequest(String xmlContent) {
        this.xmlContent = xmlContent;
    }

    public String getXmlContent() {
        return xmlContent;
    }

    public void setXmlContent(String xmlContent) {
        this.xmlContent = xmlContent;
    }
}