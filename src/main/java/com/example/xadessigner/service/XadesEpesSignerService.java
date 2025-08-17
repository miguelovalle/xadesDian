package com.example.xadessigner.service;

import com.example.xadessigner.config.CertificateConfig;
import com.example.xadessigner.dto.SignResponse;
import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.List;
import java.util.UUID;

@Service
public class XadesEpesSignerService {

    private static final Logger logger = LoggerFactory.getLogger(XadesEpesSignerService.class);

        // Conjunto para rastrear IDs únicos
    private final Set<String> usedIds = new HashSet<>();

    static {
        Init.init();
    }

    @Autowired
    private CertificateConfig certificateConfig;

    private static final String SIGNATURE_ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String DIGEST_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha256";
   
    private static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";
    private static final String XADES_SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties";
    private static final String DIAN_POLICY_ID = "https://facturaelectronica.dian.gov.co/politicadefirma/v2/politicadefirmav2.pdf";
    private static final String DIAN_POLICY_DESCRIPTION = "Política de firma para facturas electrónicas de la DIAN v2.0";
    private static final String DIAN_POLICY_HASH = "dMoMvtcG5aIzgYo0tIsSQeVJBDnUnfSOfBpxXrmor0Y=";
   
    public SignResponse signXml(String xmlContent) {
        try {
            logger.info("Iniciando proceso de firma digital");
            
            if (xmlContent == null || xmlContent.trim().isEmpty()) {
                return new SignResponse(null, false, "XML content is empty or null");
            }

            // Parsear el XML
            Document document = parseXmlString(xmlContent);
            logger.debug("XML parseado correctamente");            
            
             // Cargar certificado
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            KeyStore.PrivateKeyEntry keyEntry = loadCertificate();
            PrivateKey privateKey = keyEntry.getPrivateKey();
            X509Certificate certificate = (X509Certificate) keyEntry.getCertificate();
            String alias = certificate.getSubjectX500Principal().getName();
            logger.debug("Certificado cargado correctamente"); 

            // Crear la firma
            XMLSignature signature = createSignature(document, privateKey, certificate);
            logger.debug("Firma creada correctamente");

            // *** LIMPIAR NAMESPACES DESPUÉS DE CREAR ELEMENTOS ***
           cleanAllNamespaces(document, signature);
           logger.debug("✅ Namespaces limpiados después de crear elementos");
            
           // *** MOVER LA FIRMA ***
           logger.info("➡️  MOVING SIGNATURE TO DIAN REQUIRED LOCATION");
           moveSignatureToDianRequiredLocation(document, signature.getElement());
           logger.debug("✅ Signature moved to DIAN location");

            // Agregar elementos XAdES EPES
            addXadesEpesElements(document, signature, keyStore, alias,  certificate);
            logger.debug("Elementos XAdES EPES agregados");
            

            // LIMPIAR NAMESPACES PROBLEMÁTICOS
            logger.info("🔍 LIMPIANDO NAMESPACES PROBLEMÁTICOS");
            cleanReferenceNamespaces(signature);
            ensureProperReferenceStructure(signature);

           // Verificar estructura del Object
            verifyObjectElementStructure(signature);        

            // VERIFICACIONES PREVIAS A LA FIRMA
            logger.info("🔍 REALIZANDO VERIFICACIONES PRE-FIRMA");
            ensureAllReferencesHaveDigest(signature);
            //ensureCorrectSignatureStructure(signature);            
//             ensureReferenceTransforms(signature);

            // Calcular la firma
            signature.sign(privateKey);
            logger.info("Firma calculada correctamente");

            // Verificación post-firma
            //verifySignatureResult(signature);            
  //           verifySignatureIntegrity(signature);
            // Convertir a string
            String signedXml = documentToString(document);
            
            if (signedXml == null || signedXml.trim().isEmpty()) {
                logger.error("El XML firmado es null o vacío");
                return new SignResponse(null, false, "Error: XML firmado es null o vacío");
            }
            
            logger.debug("XML firmado generado correctamente, longitud: {}", signedXml.length());
            return new SignResponse(signedXml, true, "XML firmado correctamente");
            
        } catch (Exception e) {
            logger.error("Error al firmar XML: ", e);
            return new SignResponse(null, false, "Error al firmar XML: " + e.getMessage());
        } 
        finally {               
            // Limpiar IDs de firma para evitar duplicados en futuras firmas
            usedIds.clear();
        }
    }

    private Document parseXmlString(String xmlContent) throws Exception {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            
            // Limpiar el XML de entrada
            String cleanXml = xmlContent.trim();
            if (cleanXml.startsWith("\"") && cleanXml.endsWith("\"")) {
                cleanXml = cleanXml.substring(1, cleanXml.length() - 1);
            }
            
            return builder.parse(new ByteArrayInputStream(cleanXml.getBytes("UTF-8")));
        } catch (Exception e) {
            logger.error("Error al parsear XML: {}", xmlContent, e);
            throw new Exception("Error al parsear XML: " + e.getMessage(), e);
        }
    }

    private KeyStore.PrivateKeyEntry loadCertificate() throws Exception {
        try {
            logger.info("Cargando certificado desde: {}", certificateConfig.getPath());
            logger.info("Configuración del certificado: {}", certificateConfig.toString());
            
            // Validar configuración
            if (certificateConfig.getPath() == null || certificateConfig.getPath().isEmpty()) {
                throw new Exception("La ruta del certificado no está configurada. Verifica application.yml");
            }
            
            if (certificateConfig.getPassword() == null) {
                throw new Exception("La contraseña del certificado no está configurada. Verifica application.yml");
            }

            // Cargar el keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            
            // Cargar desde resources/certificates
            ClassPathResource resource = new ClassPathResource(certificateConfig.getPath());
            logger.debug("Buscando certificado en: {}", resource.getPath());
            
            if (!resource.exists()) {
                throw new Exception("No se encontró el certificado en: " + certificateConfig.getPath() + 
                                ". Asegúrate de que el archivo existe en src/main/resources/" + certificateConfig.getPath());
            }
            
            logger.debug("Certificado encontrado, intentando cargar...");
            InputStream keyStoreStream = null;
            try {
                keyStoreStream = resource.getInputStream();
                char[] password = certificateConfig.getPassword().toCharArray();
                
                // Intentar cargar el keystore
                keyStore.load(keyStoreStream, password);
                logger.debug("Keystore cargado exitosamente");
            } finally {
                if (keyStoreStream != null) {
                    try {
                        keyStoreStream.close();
                    } catch (IOException e) {
                        logger.warn("Error al cerrar stream del keystore", e);
                    }
                }
            }
            
            // Listar aliases disponibles para debugging
            Enumeration<String> aliases = keyStore.aliases();
            logger.debug("Aliases disponibles en el keystore:");
            int aliasCount = 0;
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                logger.debug("  - Alias {}: {}", ++aliasCount, alias);
            }
            
            if (aliasCount == 0) {
                throw new Exception("No se encontraron certificados en el keystore");
            }
            
            // Obtener el alias del certificado
            String alias;
            if (certificateConfig.getAlias() != null && !certificateConfig.getAlias().isEmpty()) {
                alias = certificateConfig.getAlias();
                logger.debug("Usando alias configurado: {}", alias);
                if (!keyStore.containsAlias(alias)) {
                    throw new Exception("El alias '" + alias + "' no existe en el keystore. " +
                                    "Aliases disponibles: " + getKeyStoreAliases(keyStore));
                }
            } else {
                // Usar el primer alias disponible
                Enumeration<String> aliasEnum = keyStore.aliases();
                if (aliasEnum.hasMoreElements()) {
                    alias = aliasEnum.nextElement();
                    logger.debug("Usando primer alias disponible: {}", alias);
                } else {
                    throw new Exception("No se encontraron certificados en el keystore");
                }
            }
            
            // Verificar que el alias existe
            if (!keyStore.containsAlias(alias)) {
                throw new Exception("El alias '" + alias + "' no existe en el keystore");
            }
            
            // Cargar la entrada del keystore
            KeyStore.PasswordProtection passwordProtection = 
                new KeyStore.PasswordProtection(certificateConfig.getPassword().toCharArray());
            KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) 
                keyStore.getEntry(alias, passwordProtection);
                
            if (keyEntry == null) {
                throw new Exception("No se pudo obtener la entrada del certificado para el alias: " + alias + 
                                ". Verifica que el certificado contiene una clave privada.");
            }
            
            logger.info("Certificado cargado exitosamente con alias: {}", alias);
            return keyEntry;
                
        } catch (Exception e) {
            logger.error("Error detallado al cargar el certificado: ", e);
            throw new Exception("Error al cargar el certificado: " + e.getMessage(), e);
        }
    }

    // Método auxiliar para listar aliases
    private String getKeyStoreAliases(KeyStore keyStore) throws Exception {
        StringBuilder aliases = new StringBuilder();
        Enumeration<String> aliasEnum = keyStore.aliases();
        while (aliasEnum.hasMoreElements()) {
            if (aliases.length() > 0) aliases.append(", ");
            aliases.append(aliasEnum.nextElement());
        }
        return aliases.toString();
    }

    private XMLSignature createSignature(Document document, PrivateKey privateKey, X509Certificate certificate) throws Exception {
        String signatureId = "xmldsig-" + UUID.randomUUID().toString();
        logger.debug("Creando firma con ID: {}", signatureId);
        
        // Crear la firma con namvespace prefijado
        XMLSignature signature = new XMLSignature(document, "", SIGNATURE_ALGORITHM);
        signature.setId(signatureId);

        Element signatureElement = signature.getElement();
        
        // Asegurar que solo se use xmlns:ds para digital signature
        signatureElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", Constants.SignatureSpecNS);

            // Remover cualquier namespace por defecto
        if (signatureElement.hasAttribute("xmlns")) {
            signatureElement.removeAttribute("xmlns");
        }

        // Agregar ID al SignatureValue
        NodeList signatureValueNodes = signature.getElement().getElementsByTagNameNS(
            Constants.SignatureSpecNS, "SignatureValue");
        if (signatureValueNodes != null && signatureValueNodes.getLength() > 0) {
            Node signatureValueNode = signatureValueNodes.item(0);
            if (signatureValueNode.getNodeType() == Node.ELEMENT_NODE) {
                Element signatureValueElement = (Element) signatureValueNode;
                String signatureValueId = signatureId + "-sigvalue";
                signatureValueElement.setAttribute("Id", signatureValueId);
                logger.debug("SignatureValue ID asignado: {}", signatureValueId);
            }
        }

        // Insertar la firma en el documento
        Element rootElement = document.getDocumentElement();
        if (rootElement != null) {
            rootElement.appendChild(signature.getElement());
            logger.debug("Firma insertada en el documento");
        } else {
            throw new Exception("No se encontró el elemento raíz del documento");
        }

        // Referencia al documento completo con ID específico
        Transforms transforms = new Transforms(document);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        
        // Agregar la primera referencia con ID
        signature.addDocument("", transforms, DIGEST_ALGORITHM, signatureId + "-ref0", null);
        logger.debug("Referencia principal agregada con ID: {}", signatureId + "-ref0");
        

        // Agregar KeyInfo
        signature.addKeyInfo(certificate);
        logger.debug("KeyInfo agregado");
        
        // Agregar ID al KeyInfo 
        NodeList keyInfoNodes = signature.getElement().getElementsByTagNameNS(
            Constants.SignatureSpecNS, "KeyInfo");
        if (keyInfoNodes != null && keyInfoNodes.getLength() > 0) {
            Node keyInfoNode = keyInfoNodes.item(keyInfoNodes.getLength() - 1);

            if (keyInfoNode.getNodeType() == Node.ELEMENT_NODE) {
                Element keyInfoElement = (Element) keyInfoNode;
                String keyInfoId = "xmldsig-" + UUID.randomUUID().toString() + "-keyinfo";
                keyInfoElement.setAttribute("Id", keyInfoId);
                logger.debug("KeyInfo ID asignado: {}", keyInfoId);
                //   addDocumentReferenceWithoutId( signature, "#" + keyInfoId,  DIGEST_ALGORITHM );
                addReferenceManually(signature, keyInfoId, false);
            }
        } 
        return signature;
    }

    private void addXadesEpesElements(Document document, XMLSignature signature, KeyStore keyStore, String alias, X509Certificate certificate) throws Exception {
     
        Element signatureElement = signature.getElement();
        logger.info("KeyStore: {}, Alias: {}", keyStore != null ? "OK" : "NULL", alias);
    
        if (keyStore == null || alias == null || alias.isEmpty()) {
            throw new Exception("KeyStore o alias inválido");
        }

    // Asegurar namespace XAdES
    if (!signatureElement.hasAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades")) {
        signatureElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades", 
            "http://uri.etsi.org/01903/v1.3.2#");
    }
        
        // Crear elemento Object
        Element objectElement = document.createElementNS(Constants.SignatureSpecNS, "Object");
         objectElement.setPrefix("ds");

   // Eliminar namespace por defecto si se agrega automáticamente
        if (objectElement.hasAttribute("xmlns")) {
        objectElement.removeAttribute("xmlns");
        }
        logger.debug("Object element - Namespace: {}, Prefix: {}, LocalName: {}", 
                objectElement.getNamespaceURI(), 
                objectElement.getPrefix(), 
                objectElement.getLocalName());
                
        signatureElement.appendChild(objectElement);
        logger.debug("✅ Elemento ds:Object creado con prefijo correcto");

        // Asegurar namespace XAdES en el elemento raíz del documento
        ensureXadesNamespace(document);        

        // Crear QualifyingProperties
        Element qualifyingProperties = document.createElementNS(
            "http://uri.etsi.org/01903/v1.3.2#", "xades:QualifyingProperties");
        qualifyingProperties.setAttribute("Target", "#" + signature.getId());
        objectElement.appendChild(qualifyingProperties);
        logger.debug("QualifyingProperties creado con Target: #{}", signature.getId());
        
        // Crear SignedProperties
        Element signedProperties = document.createElementNS(
            "http://uri.etsi.org/01903/v1.3.2#", "xades:SignedProperties");
        String signedPropertiesId =signature.getId() + "-signedprops";
        signedProperties.setAttribute("Id", signedPropertiesId);
        qualifyingProperties.appendChild(signedProperties);
        logger.debug("SignedProperties creado con ID: {}", signedPropertiesId);
        
        // Crear SignedSignatureProperties
        Element signedSigProps = document.createElementNS(
            "http://uri.etsi.org/01903/v1.3.2#", "xades:SignedSignatureProperties");
        signedProperties.appendChild(signedSigProps);
        logger.debug("SignedSignatureProperties creado");
        
        // Agregar SigningTime
        Element signingTime = document.createElementNS(
            "http://uri.etsi.org/01903/v1.3.2#", "xades:SigningTime");

        String timeFormated= addTimeIso8601();
        signingTime.setTextContent(timeFormated);
        signedSigProps.appendChild(signingTime);
        logger.debug("SigningTime agregado");
        
        // *** AGREGAR CADENA COMPLETA DE CERTIFICADOS ***
        addSigningCertificateWithCompleteChain(document, signedSigProps, keyStore, alias, certificate);

        // Agregar SignaturePolicyIdentifier (política DIAN Colombia)
        addSignaturePolicyIdentifier(document, signedSigProps);
        
        // Agregar SignerRole
        addSignerRole(document, signedSigProps);
        
        // Agregar referencia al SignedProperties
         addReferenceManually(signature,  signedPropertiesId, true);
          //addDocumentReferenceWithoutId( signature, "#" + signedPropertiesId,  DIGEST_ALGORITHM );
        logger.debug("Referencia a SignedProperties agregada con ID: {}", signedPropertiesId);
    }

    private String addTimeIso8601() {
               java.time.ZonedDateTime zonedDateTime = java.time.ZonedDateTime.now();
    
        // Formatear con control preciso
        java.time.format.DateTimeFormatter formatter = 
            new java.time.format.DateTimeFormatterBuilder()
                .appendPattern("yyyy-MM-dd'T'HH:mm:ss")
                .appendFraction(java.time.temporal.ChronoField.MILLI_OF_SECOND, 3, 3, true)
                .appendPattern("XXX")
                .toFormatter();
       
            return zonedDateTime.format(formatter);
        }
        
private void addSigningCertificateWithCompleteChain(Document document, Element signedSigProps, 
                                                   KeyStore keyStore, String alias, 
                                                   X509Certificate certificate) throws Exception {
    logger.info("=== PROCESANDO CADENA DE CERTIFICADOS ===");
    logger.info("Alias proporcionado: {}", alias);
    
    // Crear el elemento SigningCertificate
    Element signingCertificate = document.createElementNS(
        "http://uri.etsi.org/01903/v1.3.2#", "xades:SigningCertificate");
        
    signedSigProps.appendChild(signingCertificate);
    logger.debug("✅ Elemento SigningCertificate creado");
    
    // Obtener la cadena completa (debería tener 3 certificados)
    X509Certificate[] certificateChain = getCertificateChainWithFallback(alias);
    
    if (certificateChain == null || certificateChain.length == 0) {
        logger.error("❌ No se pudo obtener cadena de certificados");
        throw new Exception("No se pudo obtener cadena de certificados");
    }
    
    logger.info("📊 Procesando cadena con {} certificados", certificateChain.length);
    
    // Agregar cada certificado de la cadena
    for (int i = 0; i < certificateChain.length; i++) {
        X509Certificate cert = certificateChain[i];
        if (cert != null) {
            try {
                addSingleCertificateToChain(document, signingCertificate, cert, i);
                logger.info("✅ Certificado {} agregado", i + 1);
            } catch (Exception e) {
                logger.error("❌ Error al agregar certificado {}: {}", i + 1, e.getMessage());
                throw e;
            }
        } else {
            logger.warn("⚠️  Certificado {} es NULL", i + 1);
        }
    }
    
    logger.info("✅ CADENA DE CERTIFICADOS PROCESADA ({} certificados)", certificateChain.length);
}

private X509Certificate[] getCertificateChainWithFallback(String alias) {
    try {
        logger.info("🔄 RECARGANDO KEYSTORE PARA OBTENER CADENA COMPLETA");
        logger.info("Alias buscado: {}", alias);
        
        KeyStore freshKeyStore = KeyStore.getInstance("PKCS12");
        String certPath = certificateConfig.getPath();
        ClassPathResource resource = new ClassPathResource(certPath);
        
        if (!resource.exists()) {
            logger.error("❌ No se encontró certificado en: {}", certPath);
            return null;
        }
        
        InputStream keyStoreStream = null;
        try {
            keyStoreStream = resource.getInputStream();
            char[] password = certificateConfig.getPassword().toCharArray();
            freshKeyStore.load(keyStoreStream, password);
            logger.debug("✅ KeyStore recargado exitosamente, size: {}", freshKeyStore.size());
            
            // LISTAR TODOS LOS ALIASES PARA DEBUGGING
            logger.debug("=== ALIASES DISPONIBLES ===");
            Enumeration<String> aliases = freshKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                String availableAlias = aliases.nextElement();
                logger.debug("Alias disponible: {}", availableAlias);
            }
            logger.debug("=== FIN ALIASES ===");
            
            // PROBAR CON EL ALIAS PROPORCIONADO
            logger.debug("Intentando obtener cadena con alias original: {}", alias);
            X509Certificate[] chain = getChainFromKeyStore(freshKeyStore, alias);
            
            if (chain != null && chain.length > 0) {
                logger.info("✅ Cadena obtenida con {} certificados usando alias original", chain.length);
                logCertificateChain(chain);
                return chain;
            }
            
            // SI FALLA, INTENTAR CON OTROS ALIASES
            logger.warn("⚠️  No se obtuvo cadena con alias original, intentando otros aliases...");
            aliases = freshKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alternativeAlias = aliases.nextElement();
                if (!alternativeAlias.equals(alias)) {
                    logger.debug("Intentando con alias alternativo: {}", alternativeAlias);
                    chain = getChainFromKeyStore(freshKeyStore, alternativeAlias);
                    if (chain != null && chain.length > 0) {
                        logger.info("✅ Cadena obtenida con {} certificados usando alias alternativo", chain.length);
                        logCertificateChain(chain);
                        return chain;
                    }
                }
            }
            
            // ÚLTIMO RECURSO: Obtener solo el certificado individual
            logger.warn("⚠️  Intentando obtener certificado individual...");
            java.security.cert.Certificate singleCert = freshKeyStore.getCertificate(alias);
            if (singleCert instanceof X509Certificate) {
                X509Certificate cert = (X509Certificate) singleCert;
                logger.info("📦 Solo certificado individual encontrado");
                logCertificateInfo(cert, 1);
                return new X509Certificate[] { cert };
            }
            
        } finally {
            if (keyStoreStream != null) {
                try {
                    keyStoreStream.close();
                } catch (Exception e) {
                    logger.warn("Warning al cerrar stream: {}", e.getMessage());
                }
            }
        }
    } catch (Exception e) {
        logger.error("❌ Error al recargar KeyStore: {}", e.getMessage(), e);
    }
    
    logger.error("❌ No se pudo obtener cadena de certificados");
    return null;
}

// Método auxiliar para truncar strings largos en logs
private String truncateString(String str, int maxLength) {
    if (str == null) return "null";
    if (str.length() <= maxLength) return str;
    return str.substring(0, maxLength) + "...";
}

private X509Certificate[] getChainFromKeyStore(KeyStore keyStore, String alias) {
    try {
        logger.debug("Obteniendo cadena para alias: {}", alias);
        
        if (!keyStore.containsAlias(alias)) {
            logger.debug("Alias '{}' no existe en el KeyStore", alias);
            return null;
        }
        
        java.security.cert.Certificate[] chain = keyStore.getCertificateChain(alias);
        
        if (chain == null) {
            logger.debug("getCertificateChain devolvió NULL para alias: {}", alias);
            return null;
        }
        
        if (chain.length == 0) {
            logger.debug("Cadena vacía para alias: {}", alias);
            return null;
        }
        
        logger.debug("Cadena obtenida con {} certificados", chain.length);
        
        // Convertir a X509Certificate[]
        X509Certificate[] x509Chain = new X509Certificate[chain.length];
        for (int i = 0; i < chain.length; i++) {
            if (chain[i] instanceof X509Certificate) {
                x509Chain[i] = (X509Certificate) chain[i];
            } else {
                logger.error("Certificado {} no es X509", i + 1);
                return null;
            }
        }
        
        return x509Chain;
        
    } catch (Exception e) {
        logger.error("Error al obtener cadena de KeyStore: {}", e.getMessage());
        return null;
    }
}

private void logCertificateChain(X509Certificate[] chain) {
    logger.info("=== CADENA DE CERTIFICADOS ({} certificados) ===", chain.length);
    for (int i = 0; i < chain.length; i++) {
        X509Certificate cert = chain[i];
        logCertificateInfo(cert, i + 1);
    }
    logger.info("=== FIN CADENA ===");
}

private void logCertificateInfo(X509Certificate cert, int position) {
    String subject = cert.getSubjectX500Principal().getName();
    String issuer = cert.getIssuerX500Principal().getName();
    
    logger.info("📄 Certificado {}: {}", position, truncateString(subject, 60));
    logger.debug("   Issuer:  {}", truncateString(issuer, 60));
    logger.debug("   Serial:  {}", cert.getSerialNumber());
    
    // Determinar tipo de certificado
    if (subject.equals(issuer)) {
        logger.debug("   Tipo:    CERTIFICADO RAÍZ (Self-signed)");
    } else if (subject.contains("CN=") && issuer.contains("CN=")) {
        logger.debug("   Tipo:    CERTIFICADO INTERMEDIO o FIRMANTE");
    }
}

private void addSingleCertificateToChain(Document document, Element signingCertificateParent, 
                                        X509Certificate certificate, int position) throws Exception {
    logger.debug("Agregando certificado {} a la cadena", position + 1);

    // Crear elemento Cert
    Element certElement = document.createElementNS(
        "http://uri.etsi.org/01903/v1.3.2#", "xades:Cert");
    signingCertificateParent.appendChild(certElement);
    
    // *** CertDigest ***
    Element certDigest = document.createElementNS(
        "http://uri.etsi.org/01903/v1.3.2#", "xades:CertDigest");
    certElement.appendChild(certDigest);
    
    // DigestMethod
    Element digestMethod = document.createElementNS(
        Constants.SignatureSpecNS, "ds:DigestMethod");
    digestMethod.setAttribute("Algorithm", DIGEST_ALGORITHM);
    certDigest.appendChild(digestMethod);
    
    // DigestValue
    Element digestValue = document.createElementNS(
        Constants.SignatureSpecNS, "ds:DigestValue");
    
    // Calcular digest del certificado
    byte[] certBytes = certificate.getEncoded();
    byte[] digestBytes = calculateDigest(certBytes, DIGEST_ALGORITHM);
    String digestBase64 = java.util.Base64.getEncoder().encodeToString(digestBytes);
    digestValue.setTextContent(digestBase64);
    certDigest.appendChild(digestValue);
    
    // *** IssuerSerial ***
    Element issuerSerial = document.createElementNS(
        "http://uri.etsi.org/01903/v1.3.2#", "xades:IssuerSerial");
    certElement.appendChild(issuerSerial);
    
    // X509IssuerName - USAR ELEMENTO CORRECTO PARA DIAN
    Element x509IssuerName = document.createElementNS(
        Constants.SignatureSpecNS, "ds:X509IssuerName"); // Cambiado de xades:IssuerName a ds:X509IssuerName
    x509IssuerName.setTextContent(certificate.getIssuerX500Principal().getName());
    issuerSerial.appendChild(x509IssuerName);
    
    
    // X509SerialNumber - USAR ELEMENTO CORRECTO PARA DIAN
    Element x509SerialNumber = document.createElementNS(
        Constants.SignatureSpecNS, "ds:X509SerialNumber"); // Cambiado de xades:SerialNumber a ds:X509SerialNumber
    x509SerialNumber.setTextContent(certificate.getSerialNumber().toString());
    issuerSerial.appendChild(x509SerialNumber);
    
    logger.debug("✅ Certificado {} agregado correctamente", position + 1);
}

    private void addSignaturePolicyIdentifier(Document doc, Element signedSigProps) {
        Element sigPolicyIdentifier = doc.createElementNS(XADES_NS, "xades:SignaturePolicyIdentifier");
        Element sigPolicyId = doc.createElementNS(XADES_NS, "xades:SignaturePolicyId");
        
        // SigPolicyId
        Element identifier = doc.createElementNS(XADES_NS, "xades:Identifier");
        identifier.setTextContent(DIAN_POLICY_ID);
        Element description = doc.createElementNS(XADES_NS, "xades:Description");
        description.setTextContent(DIAN_POLICY_DESCRIPTION);
        
        Element sigPolicyIdElement = doc.createElementNS(XADES_NS, "xades:SigPolicyId");
        sigPolicyIdElement.appendChild(identifier);
        sigPolicyIdElement.appendChild(description);
        sigPolicyId.appendChild(sigPolicyIdElement);

        Element documentationReferences = doc.createElementNS(
            "http://uri.etsi.org/01903/v1.3.2#", "xades:DocumentationReferences");
        sigPolicyIdElement.appendChild(documentationReferences);
        
          // Agregar al menos una referencia de documentación
        Element documentationReference = doc.createElementNS(
            "http://uri.etsi.org/01903/v1.3.2#", "xades:DocumentationReference");
        documentationReferences.appendChild(documentationReference);

        // SigPolicyHash
        Element sigPolicyHash = doc.createElementNS(XADES_NS, "xades:SigPolicyHash");
        Element digestMethod = doc.createElementNS(Constants.SignatureSpecNS, "ds:DigestMethod");
        digestMethod.setAttributeNS(null, "Algorithm", org.apache.xml.security.algorithms.MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        Element digestValue = doc.createElementNS(Constants.SignatureSpecNS, "ds:DigestValue");
        digestValue.setTextContent(DIAN_POLICY_HASH);
        
        sigPolicyHash.appendChild(digestMethod);
        sigPolicyHash.appendChild(digestValue);
        sigPolicyId.appendChild(sigPolicyHash);



        sigPolicyIdentifier.appendChild(sigPolicyId);
        signedSigProps.appendChild(sigPolicyIdentifier);
    }


    private void addSignerRole(Document document, Element signedSigProps) {
        Element signerRole = document.createElementNS(
            "http://uri.etsi.org/01903/v1.3.2#", "xades:SignerRole");
        signedSigProps.appendChild(signerRole);
        
        Element claimedRoles = document.createElementNS(
            "http://uri.etsi.org/01903/v1.3.2#", "xades:ClaimedRoles");
        signerRole.appendChild(claimedRoles);
        
        Element claimedRole = document.createElementNS(
            "http://uri.etsi.org/01903/v1.3.2#", "xades:ClaimedRole");
        claimedRole.setTextContent("supplier");
        claimedRoles.appendChild(claimedRole);
        
        logger.debug("SignerRole agregado");
    }


    private void addReferenceManually(XMLSignature signature, String elementId, boolean bdra ) throws Exception {
        Document doc = signature.getDocument();

            // Obtener el elemento SignedInfo
        Element signedInfoElement = (Element) signature.getElement().getElementsByTagNameNS(
            Constants.SignatureSpecNS, "SignedInfo").item(0);
        
        if (signedInfoElement == null) {
            throw new Exception("No se encontró el elemento SignedInfo");
        }
        
        logger.debug("Agregando referencia a SignedInfo");
        
        // Crear elemento Reference 
        Element referenceElement = doc.createElementNS(Constants.SignatureSpecNS, "ds:Reference");
        referenceElement.setAttribute("URI", "#" + elementId);
        if (bdra ==true) {
            referenceElement.setAttribute("Type", "http://uri.etsi.org/01903#SignedProperties");
        }
        
        // Crear DigestMethod
        Element digestMethodElement = doc.createElementNS(Constants.SignatureSpecNS, "ds:DigestMethod");
        digestMethodElement.setAttribute("Algorithm", DIGEST_ALGORITHM);
        referenceElement.appendChild(digestMethodElement);
        
        // Crear DigestValue 
        Element digestValueElement = doc.createElementNS(Constants.SignatureSpecNS, "ds:DigestValue");
        referenceElement.appendChild(digestValueElement);

            // Agregar Reference al SignedInfo (NO al Signature directamente)
        signedInfoElement.appendChild(referenceElement);
        
        // Agregar Reference al Signature
    // signature.getElement().appendChild(referenceElement);
        
        // *** CALCULAR EL DIGEST MANUALMENTE ***
        calculateAndSetDigest(signature, referenceElement, "#" +  elementId);
        
        logger.debug("✅ Referencia KeyInfo manual agregada con digest calculado: URI=#{}", elementId);
    }

    private void calculateAndSetDigest(XMLSignature signature, Element referenceElement, String uri) throws Exception {
        try {
            Document doc = signature.getDocument();
            
            // Extraer el ID del URI (eliminar el #)
            String elementId = uri.substring(1); // Remover el #
            
            // Buscar el elemento por ID
            Element targetElement = doc.getElementById(elementId);
            if (targetElement == null) {
                // Si getElementById no funciona, buscar manualmente
                targetElement = findElementById(doc.getDocumentElement(), elementId);
            }
            
            if (targetElement == null) {
                throw new Exception("No se encontró el elemento con ID: " + elementId);
            }
            
            // Serializar el elemento para calcular el digest
            String elementXml = serializeElement(targetElement);
            logger.debug("Elemento a digerir: {}", elementXml);
            
            // Calcular el digest
            byte[] digestBytes = calculateDigest(elementXml.getBytes("UTF-8"), DIGEST_ALGORITHM);
            String digestBase64 = java.util.Base64.getEncoder().encodeToString(digestBytes);
            
            // Asignar el digest al DigestValue
            Element digestValueElement = (Element) referenceElement.getElementsByTagNameNS(
                Constants.SignatureSpecNS, "ds:DigestValue").item(0);
            if (digestValueElement != null) {
                digestValueElement.setTextContent(digestBase64);
                logger.debug("✅ Digest calculado y asignado: {}", digestBase64);
            }
            
        } catch (Exception e) {
            logger.error("Error al calcular digest para URI {}: {}", uri, e.getMessage());
            throw e;
        }
    }

    private Element findElementById(Element parent, String id) {
        if (id.equals(parent.getAttribute("Id"))) {
            return parent;
        }
        
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i).getNodeType() == Node.ELEMENT_NODE) {
                Element found = findElementById((Element) children.item(i), id);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private String serializeElement(Element element) throws Exception {
        // Crear un documento temporal con solo este elemento
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document tempDoc = builder.newDocument();
        
        // Importar el elemento al documento temporal
        Node importedNode = tempDoc.importNode(element, true);
        tempDoc.appendChild(importedNode);
        
        // Serializar
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(tempDoc), new StreamResult(writer));
        
        String result = writer.toString();
        // Eliminar la declaración XML si existe
        if (result.startsWith("<?xml")) {
            result = result.substring(result.indexOf(">") + 1);
        }
        
        return result.trim();
    }

    private byte[] calculateDigest(byte[] data, String algorithm) throws Exception {
        String javaAlgorithm;
        switch (algorithm) {
            case "http://www.w3.org/2001/04/xmlenc#sha256":
                javaAlgorithm = "SHA-256";
                break;
            case "http://www.w3.org/2000/09/xmldsig#sha1":
                javaAlgorithm = "SHA-1";
                break;
            default:
                throw new Exception("Algoritmo no soportado: " + algorithm);
        }
        
        java.security.MessageDigest md = java.security.MessageDigest.getInstance(javaAlgorithm);
        return md.digest(data);
    }
    // *** LIMPIEZA DE NAMESPACES DESPUÉS DE CREAR ELEMENTOS ***
    private void cleanAllNamespaces(Document document, XMLSignature signature) throws Exception {
        logger.debug("Iniciando limpieza de namespaces...");
        
        // 1. Limpiar namespaces del elemento Signature y sus hijos
        cleanSignatureNamespaces(signature.getElement());
        
        // 2. Limpiar namespaces de los elementos XAdES
        cleanXadesNamespaces(document);
        
        // 3. Configurar prefijos correctamente
        setupPrefixes(document, signature);
        
        // 4. Declarar namespaces solo una vez en el elemento raíz
        declareNamespacesOnce(document);
        
        logger.debug("✅ Limpieza de namespaces completada");
    }

    private void cleanSignatureNamespaces(Element signatureElement) {
        logger.debug("Limpiando namespaces de Signature...");
        
        // Recorrer todos los elementos hijos y limpiar namespaces redundantes
        cleanElementAndChildren(signatureElement);
    }

    private void cleanElementAndChildren(Element element) {
        // Limpiar namespace por defecto redundante
        if (element.hasAttribute("xmlns")) {
            String defaultNs = element.getAttribute("xmlns");
            if (Constants.SignatureSpecNS.equals(defaultNs)) {
                element.removeAttribute("xmlns");
                logger.debug("Removido xmlns redundante de: {}", element.getNodeName());
            }
        }
        
        // Limpiar hijos recursivamente
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i).getNodeType() == Node.ELEMENT_NODE) {
                cleanElementAndChildren((Element) children.item(i));
            }
        }
    }

    private void cleanXadesNamespaces(Document document) {
        // Limpiar namespaces redundantes en elementos XAdES
        NodeList allElements = document.getElementsByTagName("*");
        for (int i = 0; i < allElements.getLength(); i++) {
            if (allElements.item(i).getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) allElements.item(i);
                String namespaceURI = element.getNamespaceURI();
                
                // Limpiar xmlns redundantes en elementos XAdES
                if ("http://uri.etsi.org/01903/v1.3.2#".equals(namespaceURI)) {
                    if (element.hasAttribute("xmlns")) {
                        element.removeAttribute("xmlns");
                    }
                }
            }
        }
    }

    private void setupPrefixes(Document document, XMLSignature signature) {
        logger.debug("Configurando prefijos...");
        
        // Configurar prefijos para elementos Signature
        setupSignaturePrefixes(signature.getElement());
        
        // Configurar prefijos para elementos XAdES
        setupXadesPrefixes(document);
    }

    private void setupSignaturePrefixes(Element signatureElement) {
        // Aplicar prefijo ds: a todos los elementos de firma
        applyPrefixRecursively(signatureElement, "ds", Constants.SignatureSpecNS);
    }

    private void setupXadesPrefixes(Document document) {
        // Aplicar prefijo xades: a todos los elementos XAdES
        NodeList allElements = document.getElementsByTagName("*");
        for (int i = 0; i < allElements.getLength(); i++) {
            if (allElements.item(i).getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) allElements.item(i);
                String namespaceURI = element.getNamespaceURI();
                
                if ("http://uri.etsi.org/01903/v1.3.2#".equals(namespaceURI)) {
                    element.setPrefix("xades");
                }
            }
        }
    }

    private void applyPrefixRecursively(Element element, String prefix, String namespaceURI) {
        if (namespaceURI.equals(element.getNamespaceURI())) {
            element.setPrefix(prefix);
        }
        
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i).getNodeType() == Node.ELEMENT_NODE) {
                applyPrefixRecursively((Element) children.item(i), prefix, namespaceURI);
            }
        }
    }

    private void declareNamespacesOnce(Document document) {
        Element rootElement = document.getDocumentElement();
        
        // Declarar namespace digital signature
        if (!rootElement.hasAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds")) {
            rootElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", Constants.SignatureSpecNS);
        }
        
        // Declarar namespace XAdES
        if (!rootElement.hasAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades")) {
            rootElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades", 
                "http://uri.etsi.org/01903/v1.3.2#");
        }
        
        logger.debug("✅ Namespaces declarados en elemento raíz");
    }


    private String documentToString(Document document) throws Exception {
        try {
            logger.info("🔄 Convirtiendo documento a string...");
            
            if (document == null) {
                logger.error("❌ Documento es null");
                return null;
            }

            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            
            // Configuración para XML limpio
            transformer.setOutputProperty(javax.xml.transform.OutputKeys.INDENT, "no");
            transformer.setOutputProperty(javax.xml.transform.OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty(javax.xml.transform.OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(javax.xml.transform.OutputKeys.STANDALONE, "no");
            
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(document), new StreamResult(writer));
            
            String result = writer.getBuffer().toString();
            
            logger.debug("🔄 Transformación completada, longitud antes de limpieza: {}", 
                result != null ? result.length() : 0);
            
            if (result == null || result.trim().isEmpty()) {
                logger.error("❌ Resultado de transformación es null o vacío");
                return null;
            }
// Limpieza específica para evitar namespaces heredados incorrectamente
        result = cleanInheritedNamespaces(result);


            // Limpieza adicional de na     mespaces redundantes
            result = cleanRedundantNamespaces(result);
            
            // Eliminar espacios en blanco innecesarios entre etiquetas
            result = result.replaceAll(">\\s*<", "><");
            
            // Eliminar espacios al inicio y final
            result = result.trim();
            
            logger.info("✅ XML generado correctamente, longitud final: {}", result.length());
            
            if (result.length() > 0) {
                logger.debug("📤 Primeros 200 caracteres: {}", 
                    result.substring(0, Math.min(200, result.length())));
            }
                    
            return result;
        } catch (Exception e) {
            logger.error("💥 Error al convertir documento a string: ", e);
            throw new Exception("Error al formatear XML: " + e.getMessage(), e);
        }
    }
private void moveSignatureToDianRequiredLocation(Document document, Element signatureElement) throws Exception {
    logger.info("=== MOVING SIGNATURE TO DIAN REQUIRED LOCATION ===");
    
    try {
        // Buscar todas las apariciones de ExtensionContent
        NodeList extensionContentNodes = document.getElementsByTagNameNS(
            "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2", 
            "ExtensionContent");
        
        logger.debug("Found {} ExtensionContent nodes", extensionContentNodes.getLength());
        
        // Verificar que existan al menos 2 ExtensionContent
        if (extensionContentNodes.getLength() < 2) {
            logger.warn("⚠️  Less than 2 ExtensionContent nodes found, looking for alternative locations");
            
            // Buscar por nombre local si el namespace no funciona
            extensionContentNodes = findExtensionContentNodesByLocalName(document);
            logger.debug("Found {} ExtensionContent nodes (by local name)", extensionContentNodes.getLength());
        }
        
        if (extensionContentNodes.getLength() >= 2) {
            // Usar la segunda aparición (índice 1)
            Node secondExtensionContent = extensionContentNodes.item(1);
            if (secondExtensionContent.getNodeType() == Node.ELEMENT_NODE) {
                Element extensionContentElement = (Element) secondExtensionContent;
                
                // Mover la firma a este elemento
                moveSignatureElement(signatureElement, extensionContentElement);
                logger.info("✅ Signature moved to second ExtensionContent successfully");
                return;
            }
        }
        
        // Si no se encuentra la segunda aparición, buscar ubicación alternativa
        logger.warn("⚠️  Second ExtensionContent not found, looking for alternative DIAN locations");
        moveSignatureToAlternativeDianLocation(document, signatureElement);
        
    } catch (Exception e) {
        logger.error("❌ Error moving signature to DIAN location: {}", e.getMessage(), e);
        throw new Exception("Failed to move signature to DIAN required location", e);
    }
}

private NodeList findExtensionContentNodesByLocalName(Document document) {
    try {
        // Buscar todos los elementos con nombre local "ExtensionContent"
        List<Element> extensionElements = new ArrayList<>();
        
        NodeList allElements = document.getElementsByTagName("*");
        for (int i = 0; i < allElements.getLength(); i++) {
            Node node = allElements.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) node;
                if ("ExtensionContent".equals(element.getLocalName()) || 
                    "ExtensionContent".equals(element.getNodeName())) {
                    extensionElements.add(element);
                }
            }
        }
        
        // Convertir lista a NodeList simulado
        return new NodeList() {
            @Override
            public Node item(int index) {
                return index < extensionElements.size() ? extensionElements.get(index) : null;
            }
            
            @Override
            public int getLength() {
                return extensionElements.size();
            }
        };
        
    } catch (Exception e) {
        logger.error("Error finding ExtensionContent nodes: {}", e.getMessage());
        return new NodeList() {
            @Override
            public Node item(int index) { return null; }
            @Override
            public int getLength() { return 0; }
        };
    }
}

private void moveSignatureElement(Element signatureElement, Element targetExtensionContent) throws Exception {
    logger.debug("Moving signature element to target ExtensionContent");
    
    // Remover la firma de su ubicación actual
    Node parent = signatureElement.getParentNode();
    if (parent != null) {
        parent.removeChild(signatureElement);
        logger.debug("Signature removed from current location");
    }
    
    // Agregar la firma al ExtensionContent target
    targetExtensionContent.appendChild(signatureElement);
    logger.debug("Signature appended to target ExtensionContent");
    
    // Verificar que se movió correctamente
    logger.debug("Signature new parent: {}", signatureElement.getParentNode().getNodeName());
}

    private void moveSignatureToAlternativeDianLocation(Document document, Element signatureElement) throws Exception {
        logger.info("=== MOVING SIGNATURE TO ALTERNATIVE DIAN LOCATION ===");
        
        // Estrategia alternativa 1: Buscar en AdditionalDocumentReference
        NodeList additionalDocRefs = document.getElementsByTagNameNS(
            "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2", 
            "AdditionalDocumentReference");
        
        if (additionalDocRefs.getLength() > 0) {
            Node firstAdditionalDocRef = additionalDocRefs.item(0);
            if (firstAdditionalDocRef.getNodeType() == Node.ELEMENT_NODE) {
                Element additionalDocRefElement = (Element) firstAdditionalDocRef;
                
                // Buscar o crear ExtensionContent dentro de AdditionalDocumentReference
                NodeList extensionContents = additionalDocRefElement.getElementsByTagNameNS(
                    "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2", 
                    "ExtensionContent");
                
                Element targetExtensionContent;
                if (extensionContents.getLength() > 0) {
                    targetExtensionContent = (Element) extensionContents.item(0);
                } else {
                    // Crear ExtensionContent si no existe
                    targetExtensionContent = document.createElementNS(
                        "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2", 
                        "ext:ExtensionContent");
                    additionalDocRefElement.appendChild(targetExtensionContent);
                }
                
                moveSignatureElement(signatureElement, targetExtensionContent);
                logger.info("✅ Signature moved to AdditionalDocumentReference ExtensionContent");
                return;
            }
        }
        
        // Estrategia alternativa 2: Crear ubicación requerida
        logger.warn("⚠️  Creating required DIAN structure");
        createDianSignatureStructure(document, signatureElement);
    }

    private void createDianSignatureStructure(Document document, Element signatureElement) throws Exception {
        logger.debug("Creating DIAN required signature structure");
        
        Element rootElement = document.getDocumentElement();
        
        // Crear UBLExtensions si no existe
        NodeList ublExtensionsList = document.getElementsByTagNameNS(
            "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2", 
            "UBLExtensions");
        
        Element ublExtensions;
        if (ublExtensionsList.getLength() == 0) {
            ublExtensions = document.createElementNS(
                "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2", 
                "ext:UBLExtensions");
            // Insertar al principio del documento
            Node firstChild = rootElement.getFirstChild();
            if (firstChild != null) {
                rootElement.insertBefore(ublExtensions, firstChild);
            } else {
                rootElement.appendChild(ublExtensions);
            }
        } else {
            ublExtensions = (Element) ublExtensionsList.item(0);
        }
        
        // Crear UBLExtension
        Element ublExtension = document.createElementNS(
            "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2", 
            "UBLExtension");
        ublExtensions.appendChild(ublExtension);
        
        // Crear ExtensionContent
        Element extensionContent = document.createElementNS(
            "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2", 
            "ext:ExtensionContent");
        ublExtension.appendChild(extensionContent);
        
        // Mover la firma
        moveSignatureElement(signatureElement, extensionContent);
        logger.info("✅ DIAN signature structure created and signature moved");
    }

private void ensureAllReferencesHaveDigest(XMLSignature signature) throws Exception {
    try {
        NodeList referenceNodes = signature.getElement().getElementsByTagNameNS(
            Constants.SignatureSpecNS, "Reference");
        
        logger.debug("Preparando {} referencias para firma", referenceNodes.getLength());
        
        for (int i = 0; i < referenceNodes.getLength(); i++) {
            Element referenceElement = (Element) referenceNodes.item(i);
            NodeList digestValueNodes = referenceElement.getElementsByTagNameNS(
                Constants.SignatureSpecNS, "DigestValue");
            
            if (digestValueNodes.getLength() > 0) {
                Element digestValueElement = (Element) digestValueNodes.item(0);
                String digestValue = digestValueElement.getTextContent();
                
                if (digestValue == null || digestValue.trim().isEmpty()) {
                    logger.info("🔄 Referencia {} necesita cálculo de digest", i);
                    
                    // Calcular manualmente el digest
                    calculateReferenceDigestManually(signature, referenceElement, i);
                } else {
                    logger.debug("✅ Referencia {} digest ya calculado", i);
                }
            }
        }
        
    } catch (Exception e) {
        logger.error("Error en preparación de referencias: {}", e.getMessage());
    }
}

private void calculateReferenceDigestManually(XMLSignature signature, Element referenceElement, int refIndex) throws Exception {
    try {
        String uri = referenceElement.getAttribute("URI");
        logger.debug("Calculando digest para referencia {} con URI: '{}'", refIndex, uri);
        
        // Obtener algoritmo de digest
        NodeList digestMethodNodes = referenceElement.getElementsByTagNameNS(
            Constants.SignatureSpecNS, "DigestMethod");
        
        if (digestMethodNodes.getLength() > 0) {
            Element digestMethodElement = (Element) digestMethodNodes.item(0);
            String algorithm = digestMethodElement.getAttribute("Algorithm");
            logger.debug("Algoritmo de digest: {}", algorithm);
            
            byte[] contentToDigest = null;
            
            if (uri == null || uri.isEmpty()) {
                // Referencia al documento completo - URI=""
                logger.debug("Calculando digest para documento completo (enveloped)");
                contentToDigest = calculateDocumentDigestContent(signature);
            } else if (uri.startsWith("#")) {
                // Referencia a elemento por ID
                String elementId = uri.substring(1);
                logger.debug("Calculando digest para elemento: {}", elementId);
                contentToDigest = calculateElementDigestContent(signature, elementId);
            }
            
            if (contentToDigest != null && contentToDigest.length > 0) {
                // Calcular digest
                byte[] digestBytes = calculateDigest(contentToDigest, algorithm);
                String digestBase64 = java.util.Base64.getEncoder().encodeToString(digestBytes);
                
                // Asignar digest calculado
                NodeList digestValueNodes = referenceElement.getElementsByTagNameNS(
                    Constants.SignatureSpecNS, "DigestValue");
                if (digestValueNodes.getLength() > 0) {
                    Element digestValueElement = (Element) digestValueNodes.item(0);
                    digestValueElement.setTextContent(digestBase64);
                    logger.info("✅ Digest calculado para referencia {}: {}", 
                               refIndex, digestBase64.substring(0, Math.min(20, digestBase64.length())) + "...");
                }
            } else {
                logger.warn("⚠️  No se pudo obtener contenido para digest de referencia {}", refIndex);
            }
        }
        
    } catch (Exception e) {
        logger.error("Error calculando digest para referencia {}: {}", refIndex, e.getMessage());
        // No lanzar excepción para permitir que Apache Santuario lo intente
    }
}

private byte[] calculateDocumentDigestContent(XMLSignature signature) throws Exception {
    try {
        logger.debug("Calculando contenido para digest de documento completo");
        
        Document doc = signature.getDocument();
        Element signatureElement = signature.getElement();
        
        // Crear copia del documento sin la firma para cálculo enveloped
        Document tempDoc = createDocumentWithoutSignature(doc, signatureElement);
        
        // Aplicar transformación enveloped y canonicalización
        org.apache.xml.security.c14n.Canonicalizer canon = 
            org.apache.xml.security.c14n.Canonicalizer.getInstance(
                org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        canon.canonicalizeSubtree(tempDoc.getDocumentElement(), baos);
        byte[] canonicalBytes = baos.toByteArray();
        
        logger.debug("Contenido canonicalizado generado: {} bytes", canonicalBytes.length);
        return canonicalBytes;
        
    } catch (Exception e) {
        logger.error("Error calculando contenido de documento: {}", e.getMessage());
        throw e;
    }
}

private byte[] calculateElementDigestContent(XMLSignature signature, String elementId) throws Exception {
    try {
        logger.debug("Calculando contenido para digest de elemento: {}", elementId);
        
        Document doc = signature.getDocument();
        
        // Buscar elemento por ID
        Element targetElement = doc.getElementById(elementId);
        if (targetElement == null) {
            targetElement = findElementById(doc.getDocumentElement(), elementId);
        }
        
        if (targetElement != null) {
            // Aplicar canonicalización
            org.apache.xml.security.c14n.Canonicalizer canon = 
                org.apache.xml.security.c14n.Canonicalizer.getInstance(
                    org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
            
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            canon.canonicalizeSubtree(targetElement, baos);
            byte[] canonicalBytes = baos.toByteArray();
            
            logger.debug("Elemento {} canonicalizado: {} bytes", elementId, canonicalBytes.length);
            return canonicalBytes;
        } else {
            logger.error("No se encontró elemento con ID: {}", elementId);
            return null;
        }
        
    } catch (Exception e) {
        logger.error("Error calculando contenido de elemento {}: {}", elementId, e.getMessage());
        throw e;
    }
}

private Document createDocumentWithoutSignature(Document originalDoc, Element signatureElement) throws Exception {
    // Crear nueva factoría de documentos
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    DocumentBuilder builder = factory.newDocumentBuilder();
    Document tempDoc = builder.newDocument();
    
    // Importar el documento completo
    Node importedRoot = tempDoc.importNode(originalDoc.getDocumentElement(), true);
    tempDoc.appendChild(importedRoot);
    
    // Remover temporalmente la firma específica del documento copiado
    NodeList signatures = tempDoc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature");
    for (int i = 0; i < signatures.getLength(); i++) {
        Element sig = (Element) signatures.item(i);
        if (signatureElement.hasAttribute("Id") && sig.hasAttribute("Id")) {
            if (sig.getAttribute("Id").equals(signatureElement.getAttribute("Id"))) {
                sig.getParentNode().removeChild(sig);
                logger.debug("Firma removida de documento temporal para cálculo enveloped");
                break;
            }
        }
    }
    
    return tempDoc;
}



/* 
private void ensureCorrectSignatureStructure(XMLSignature signature) throws Exception {
    Element signatureElement = signature.getElement();
    
    // Verificar que SignedInfo esté primero
    NodeList childNodes = signatureElement.getChildNodes();
    boolean signedInfoFound = false;
    boolean signatureValueFound = false;
    
    for (int i = 0; i < childNodes.getLength(); i++) {
        Node node = childNodes.item(i);
        if (node.getNodeType() == Node.ELEMENT_NODE) {
            Element element = (Element) node;
            String localName = element.getLocalName();
            
            if ("SignedInfo".equals(localName)) {
                signedInfoFound = true;
            } else if ("SignatureValue".equals(localName)) {
                signatureValueFound = true;
                if (!signedInfoFound) {
                    logger.error("❌ SignatureValue aparece antes de SignedInfo");
                }
            }
        }
    }
    
    logger.debug("Estructura de firma verificada - SignedInfo: {}, SignatureValue: {}", 
                signedInfoFound, signatureValueFound);
}

private void verifySignatureResult(XMLSignature signature) throws Exception {
    try {
        Element signatureElement = signature.getElement();
        
        // Verificar SignatureValue
        NodeList signatureValueNodes = signatureElement.getElementsByTagNameNS(
            Constants.SignatureSpecNS, "SignatureValue");
        
        if (signatureValueNodes.getLength() > 0) {
            Element signatureValueElement = (Element) signatureValueNodes.item(0);
            String signatureValue = signatureValueElement.getTextContent();
            
            if (signatureValue != null && !signatureValue.trim().isEmpty()) {
                logger.debug("✅ SignatureValue generado con {} caracteres", signatureValue.length());
            } else {
                logger.error("❌ SignatureValue está vacío");
            }
        } else {
            logger.error("❌ No se encontró SignatureValue");
        }
        
        // Verificar SignedInfo
        NodeList signedInfoNodes = signatureElement.getElementsByTagNameNS(
            Constants.SignatureSpecNS, "SignedInfo");
        
        if (signedInfoNodes.getLength() > 0) {
            logger.debug("✅ SignedInfo encontrado");
        } else {
            logger.error("❌ No se encontró SignedInfo");
        }
        
    } catch (Exception e) {
        logger.error("Error en verificación post-firma: {}", e.getMessage());
    }
} */

private void cleanReferenceNamespaces(XMLSignature signature) throws Exception {
    try {
        NodeList referenceNodes = signature.getElement().getElementsByTagNameNS(
            Constants.SignatureSpecNS, "Reference");
        
        logger.debug("Limpiando namespaces de {} referencias", referenceNodes.getLength());
        
        for (int i = 0; i < referenceNodes.getLength(); i++) {
            Element referenceElement = (Element) referenceNodes.item(i);
            
            // Eliminar namespace por defecto si apunta a xmldsig
            if (referenceElement.hasAttribute("xmlns")) {
                String defaultNs = referenceElement.getAttribute("xmlns");
                if (Constants.SignatureSpecNS.equals(defaultNs)) {
                    referenceElement.removeAttribute("xmlns");
                    logger.debug("✅ Namespace por defecto eliminado de referencia {}", i);
                }
            }
            
            // Asegurar que use prefijo ds: en lugar de namespace por defecto
            referenceElement.setPrefix("ds");
            
            // Limpiar también elementos hijos
            cleanChildElementsNamespaces(referenceElement);
        }
        
    } catch (Exception e) {
        logger.error("Error limpiando namespaces de referencias: {}", e.getMessage());
    }
}

private void cleanChildElementsNamespaces(Element parentElement) {
    // Limpiar namespaces de elementos hijos
    NodeList children = parentElement.getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
        if (children.item(i).getNodeType() == Node.ELEMENT_NODE) {
            Element childElement = (Element) children.item(i);
            
            // Eliminar namespace por defecto
            if (childElement.hasAttribute("xmlns")) {
                String defaultNs = childElement.getAttribute("xmlns");
                if (Constants.SignatureSpecNS.equals(defaultNs)) {
                    childElement.removeAttribute("xmlns");
                }
            }
            
            // Establecer prefijo
            childElement.setPrefix("ds");
            
            // Recursivamente limpiar hijos
            cleanChildElementsNamespaces(childElement);
        }
    }
}

private void ensureProperReferenceStructure(XMLSignature signature) throws Exception {
    try {
        NodeList referenceNodes = signature.getElement().getElementsByTagNameNS(
            Constants.SignatureSpecNS, "Reference");
        
        for (int i = 0; i < referenceNodes.getLength(); i++) {
            Element referenceElement = (Element) referenceNodes.item(i);
            String uri = referenceElement.getAttribute("URI");
            
            // Para la referencia al SignedProperties
            if (uri != null && uri.startsWith("#") && uri.contains("signedprops")) {
                logger.debug("Limpiando referencia al SignedProperties: {}", uri);
                
                // Eliminar namespace por defecto
                if (referenceElement.hasAttribute("xmlns")) {
                    referenceElement.removeAttribute("xmlns");
                }
                
                // Asegurar estructura correcta
                ensureSignedPropertiesReferenceStructure(referenceElement);
            }
        }
        
    } catch (Exception e) {
        logger.error("Error asegurando estructura de referencias: {}", e.getMessage());
    }
}

private void ensureSignedPropertiesReferenceStructure(Element referenceElement) {
    try {
        // Verificar que tenga Type correcto
        String type = referenceElement.getAttribute("Type");
        if (!"http://uri.etsi.org/01903#SignedProperties".equals(type)) {
            referenceElement.setAttribute("Type", "http://uri.etsi.org/01903#SignedProperties");
            logger.debug("✅ Type corregido para SignedProperties reference");
        }
        
        // Limpiar atributos innecesarios
        if (referenceElement.hasAttribute("xmlns")) {
            referenceElement.removeAttribute("xmlns");
        }
        
        // Asegurar prefijo correcto
        referenceElement.setPrefix("ds");
        
    } catch (Exception e) {
        logger.error("Error corrigiendo estructura de SignedProperties reference: {}", e.getMessage());
    }
}
private String cleanRedundantNamespaces(String xml) {
    try {
        // Eliminar declaraciones de namespace redundantes para xmldsig
        xml = xml.replaceAll("\\s+xmlns=\"http://www\\.w3\\.org/2000/09/xmldsig#\"", "");
        
        // Eliminar múltiples espacios consecutivos que puedan quedar
        xml = xml.replaceAll("\\s+", " ");
        
        // Limpiar espacios innecesarios alrededor de signos igual
        xml = xml.replaceAll("\\s*=\\s*", "=");
        
        // Limpiar espacios antes de cierre de etiquetas
        xml = xml.replaceAll("\\s*>", ">");
        
        return xml;
    } catch (Exception e) {
        logger.warn("Error en limpieza de namespaces: {}", e.getMessage());
        return xml; // Devolver XML original si falla la limpieza
    }
}

/* private void addSignedPropertiesReference(XMLSignature signature, String signedPropertiesId) throws Exception {
    try {
        logger.debug("Agregando referencia al SignedProperties con ID: {}", signedPropertiesId);
        
        // Crear referencia al SignedProperties con Type específico
        String signedPropsReferenceId = generateUniqueId("sigpropsref");
        
        signature.addDocument(
            "#" + signedPropertiesId,           // URI
            null,                               // transforms
            DIGEST_ALGORITHM,                  // digest algorithm
            signedPropsReferenceId,            // reference ID
            "http://uri.etsi.org/01903#SignedProperties"  // type
        );
        
        logger.debug("✅ Referencia al SignedProperties agregada con Type correcto");
        
        // Opcional: Limpiar la referencia recién creada si es necesario
        cleanLastReferenceIfSignedProperties(signature, signedPropertiesId);
        
    } catch (Exception e) {
        logger.error("Error al agregar referencia SignedProperties: {}", e.getMessage());
        throw e;
    }
} */

/* private void cleanLastReferenceIfSignedProperties(XMLSignature signature, String signedPropertiesId) {
    try {
        // Obtener todas las referencias
        NodeList referenceNodes = signature.getElement().getElementsByTagNameNS(
            Constants.SignatureSpecNS, "Reference");
        
        if (referenceNodes.getLength() > 0) {
            // Obtener la última referencia agregada
            Element lastReference = (Element) referenceNodes.item(referenceNodes.getLength() - 1);
            String uri = lastReference.getAttribute("URI");
            
            // Verificar si es la referencia al SignedProperties
            if (uri != null && uri.contains(signedPropertiesId)) {
                // Eliminar namespace por defecto si existe
                if (lastReference.hasAttribute("xmlns")) {
                    String defaultNs = lastReference.getAttribute("xmlns");
                    if (Constants.SignatureSpecNS.equals(defaultNs)) {
                        lastReference.removeAttribute("xmlns");
                        logger.debug("✅ Namespace por defecto eliminado de referencia SignedProperties");
                    }
                }
                
                // Asegurar prefijo correcto
                lastReference.setPrefix("ds");
                
                logger.debug("✅ Referencia SignedProperties limpiada y configurada");
            }
        }
    } catch (Exception e) {
        logger.warn("Nota: No se pudo limpiar referencia SignedProperties: {}", e.getMessage());
    }
}
 */

 private void ensureXadesNamespace(Document document) {
    Element rootElement = document.getDocumentElement();
    
    // Asegurar que el namespace XAdES esté declarado en el elemento raíz
    if (!rootElement.hasAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades")) {
        rootElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades", 
            "http://uri.etsi.org/01903/v1.3.2#");
        logger.debug("✅ Namespace xades: declarado en elemento raíz");
    }
    
    // Asegurar que el namespace XMLDSIG esté declarado
    if (!rootElement.hasAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds")) {
        rootElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", 
            "http://www.w3.org/2000/09/xmldsig#");
        logger.debug("✅ Namespace ds: declarado en elemento raíz");
    }
}

private String cleanInheritedNamespaces(String xml) {
    try {
        // Eliminar declaraciones de namespace redundantes
        xml = xml.replaceAll("xmlns=\"urn:oasis:names:specification:ubl:schema:xsd:Invoice-2\"", "");
        
        // Asegurar que los elementos ds: tengan el namespace correcto
        // Esta limpieza es adicional, ya que el problema principal está en la creación
        
        return xml;
    } catch (Exception e) {
        logger.warn("Advertencia en limpieza de namespaces: {}", e.getMessage());
        return xml;
    }
}
private void verifyObjectElementStructure(XMLSignature signature) {
    try {
        NodeList objectNodes = signature.getElement().getElementsByTagNameNS(
            Constants.SignatureSpecNS, "Object");
        
        for (int i = 0; i < objectNodes.getLength(); i++) {
            Element objectElement = (Element) objectNodes.item(i);
            logger.debug("Verificando Object {} - Namespace: {}, Prefix: {}", 
                        i, objectElement.getNamespaceURI(), objectElement.getPrefix());
            
            // Asegurar estructura correcta
            if (!"ds".equals(objectElement.getPrefix())) {
                objectElement.setPrefix("ds");
                logger.debug("Corregido prefijo de Object {}", i);
            }
        }
    } catch (Exception e) {
        logger.debug("Nota en verificación de Object: {}", e.getMessage());
    }
}
}