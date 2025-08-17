package com.example.xadessigner.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class SignResponse {
    @JsonProperty("signedXml")
    private String signedXml;
    
    @JsonProperty("success")
    private boolean success;
    
    @JsonProperty("message")
    private String message;

    public SignResponse() {}

    public SignResponse(String signedXml, boolean success, String message) {
        this.signedXml = signedXml;
        this.success = success;
        this.message = message;
    }

    // Getters y Setters con anotaciones explícitas
    public String getSignedXml() { 
        return signedXml; 
    }
    
    public void setSignedXml(String signedXml) { 
        this.signedXml = signedXml; 
    }
    
    public boolean isSuccess() { 
        return success; 
    }
    
    public void setSuccess(boolean success) { 
        this.success = success; 
    }
    
    public String getMessage() { 
        return message; 
    }
    
    public void setMessage(String message) { 
        this.message = message; 
    }
    
    @Override
    public String toString() {
        return "SignResponse{" +
                "signedXml='" + (signedXml != null ? signedXml.length() + " chars" : "null") + '\'' +
                ", success=" + success +
                ", message='" + message + '\'' +
                '}';
    }
}