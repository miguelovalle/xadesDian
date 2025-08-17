package com.example.xadessigner.controller;

import com.example.xadessigner.dto.SignRequest;
import com.example.xadessigner.dto.SignResponse;
import com.example.xadessigner.service.XadesEpesSignerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sign")
@CrossOrigin(origins = "*")
public class SignatureController {

    private static final Logger logger = LoggerFactory.getLogger(SignatureController.class);

    @Autowired
    private XadesEpesSignerService signerService;

    @PostMapping("/xades-epes")
    public ResponseEntity<SignResponse> signXml(@RequestBody SignRequest request) {
        logger.info("=== INICIO SOLICITUD FIRMA XAdES EPES ===");
        
        if (request == null) {
            logger.error("❌ Request es null");
            SignResponse errorResponse = new SignResponse(null, false, "Request is null");
            return ResponseEntity.badRequest().body(errorResponse);
        }
        
        logger.info("📥 Recibido XML de longitud: {}", 
            request.getXmlContent() != null ? request.getXmlContent().length() : 0);
        
        if (request.getXmlContent() == null || request.getXmlContent().trim().isEmpty()) {
            logger.warn("⚠️ XML content is empty or null");
            SignResponse errorResponse = new SignResponse(null, false, "XML content is required");
            return ResponseEntity.badRequest().body(errorResponse);
        }

        try {
            logger.info("🔄 Procesando firma...");
            SignResponse response = signerService.signXml(request.getXmlContent());
            
            if (response == null) {
                logger.error("❌ Respuesta del servicio es null");
                SignResponse errorResponse = new SignResponse(null, false, "Internal service error - response null");
                return ResponseEntity.internalServerError().body(errorResponse);
            }
            
            logger.info("✅ Proceso completado - Success: {}, Message: {}", 
                response.isSuccess(), response.getMessage());
            
            if (response.isSuccess()) {
                if (response.getSignedXml() == null) {
                    logger.error("❌ XML firmado es null");
                    SignResponse errorResponse = new SignResponse(null, false, "Signed XML is null");
                    return ResponseEntity.internalServerError().body(errorResponse);
                } else if (response.getSignedXml().trim().isEmpty()) {
                    logger.error("❌ XML firmado está vacío");
                    SignResponse errorResponse = new SignResponse(null, false, "Signed XML is empty");
                    return ResponseEntity.internalServerError().body(errorResponse);
                } else {
                    logger.info("📤 XML firmado generado, longitud: {}", response.getSignedXml().length());
                    logger.debug("📤 Contenido (primeros 200 chars): {}", 
                        response.getSignedXml().substring(0, Math.min(200, response.getSignedXml().length())));
                }
            } else {
                logger.error("❌ Error en firma: {}", response.getMessage());
            }
            
            logger.info("=== FIN SOLICITUD FIRMA XAdES EPES ===");
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("💥 Excepción no controlada: ", e);
            SignResponse errorResponse = new SignResponse(null, false, "Unexpected error: " + e.getMessage());
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    @PostMapping(value = "/xades-epes-raw", produces = "application/xml;charset=UTF-8")
    public ResponseEntity<String> signXmlRaw(@RequestBody(required = false) SignRequest request) {
        logger.info("=== INICIO SOLICITUD FIRMA XAdES EPES (RAW) ===");
        
        if (request == null) {
            String errorMsg = "❌ Request is null";
            logger.error(errorMsg);
            return ResponseEntity.badRequest().body(errorMsg);
        }
        
        if (request.getXmlContent() == null || request.getXmlContent().trim().isEmpty()) {
            String errorMsg = "⚠️ XML content is required";
            logger.warn(errorMsg);
            return ResponseEntity.badRequest().body(errorMsg);
        }

        try {
            SignResponse response = signerService.signXml(request.getXmlContent());
            if (response == null) {
                String errorMsg = "💥 Internal service error - response null";
                logger.error(errorMsg);
                return ResponseEntity.internalServerError().body(errorMsg);
            }
            
            if (response.isSuccess()) {
                if (response.getSignedXml() == null || response.getSignedXml().trim().isEmpty()) {
                    String errorMsg = "❌ Signed XML is empty or null";
                    logger.error(errorMsg);
                    return ResponseEntity.internalServerError().body(errorMsg);
                }
                logger.info("✅ XML firmado devuelto, longitud: {}", response.getSignedXml().length());
                logger.info("=== FIN SOLICITUD FIRMA XAdES EPES (RAW) ===");
                return ResponseEntity.ok(response.getSignedXml());
            } else {
                String errorMsg = "❌ Error: " + response.getMessage();
                logger.error(errorMsg);
                return ResponseEntity.badRequest().body(errorMsg);
            }
        } catch (Exception e) {
            String errorMsg = "💥 Unexpected error: " + e.getMessage();
            logger.error("💥 Excepción no controlada: ", e);
            return ResponseEntity.internalServerError().body(errorMsg);
        }
    }

    @PostMapping("/test-xml")
    public ResponseEntity<String> testXml(@RequestBody(required = false) SignRequest request) {
        logger.info("🧪 Test endpoint called");
        
        if (request == null || request.getXmlContent() == null) {
            return ResponseEntity.ok("<test><status>received_null</status></test>");
        }
        
        String xml = request.getXmlContent();
        logger.info("📥 Recibido XML de {} caracteres", xml.length());
        logger.debug("📥 Contenido: {}", xml);
        
        // Intentar parsear el XML
        try {
            javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(new java.io.ByteArrayInputStream(xml.getBytes("UTF-8")));
            
            String response = "<test><status>ok</status><received_chars>" + xml.length() + "</received_chars></test>";
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("❌ Error al parsear XML: ", e);
            return ResponseEntity.ok("<test><status>parse_error</status><error>" + e.getMessage() + "</error></test>");
        }
    }
    
    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        logger.info("🏥 Health check endpoint called");
        return ResponseEntity.ok("XAdES Signer API is running");
    }
}