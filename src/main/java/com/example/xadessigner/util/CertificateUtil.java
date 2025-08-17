// CertificateUtil.java
package com.example.xadessigner.util;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
@Component
public class CertificateUtil {

    private static final String KEYSTORE_PATH = "certificates/Certifica.p12";
    private static final String KEYSTORE_TYPE = "PKCS12";
    
    private static final Logger logger = LoggerFactory.getLogger(CertificateUtil.class);

    public static KeyStore.PrivateKeyEntry loadCertificate(String password) throws Exception {
        // Cargar keystore
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        
        ClassPathResource resource = new ClassPathResource(KEYSTORE_PATH);
        try (InputStream keyStoreStream = resource.getInputStream()) {
            keyStore.load(keyStoreStream, password.toCharArray());
        }

        // Obtener alias del certificado
        String alias = keyStore.aliases().nextElement();
        
        // Obtener clave privada y certificado
        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) 
            keyStore.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));

         
            InputStream keyStoreStream = null;
      //  char[] password = certificateConfig.getPassword().toCharArray();
        
        try {
            keyStoreStream = resource.getInputStream();
            
            // Cargar el keystore - ESTA ES LA PARTE CRÍTICA
            keyStore.load(keyStoreStream, password.toCharArray());
            logger.debug("✅ Keystore cargado exitosamente");
            
            // Verificar que esté inicializado
            if (keyStore.size() == -1) { // -1 indica no inicializado en algunas implementaciones
                throw new Exception("KeyStore no inicializado correctamente");
            }
            
            logger.debug("✅ KeyStore inicializado con {} entradas", keyStore.size());
            
        } finally {
            if (keyStoreStream != null) {
                try {
                    keyStoreStream.close();
                } catch (IOException e) {
                    logger.warn("Error al cerrar stream del keystore", e);
                }
            }
        }

        return keyEntry;
    }
}
