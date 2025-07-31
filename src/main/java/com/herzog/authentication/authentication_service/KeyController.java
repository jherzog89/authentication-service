package com.herzog.authentication.authentication_service;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@RestController
public class KeyController {
    private final RSAKey rsaKey;

    public KeyController(RSAKey rsaKey) {
        this.rsaKey = rsaKey;
    }

    @GetMapping("/public-key")
    public String getPublicKey() throws Exception {
        RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
        // Encode the public key in X.509 format and then Base64
        byte[] encoded = publicKey.getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(encoded);
        // Format as PEM
        return "-----BEGIN PUBLIC KEY-----\n" +
               base64Key.replaceAll("(.{64})", "$1\n") +
               "\n-----END PUBLIC KEY-----";
    }
    @GetMapping("/public-key/base64")
public String getPublicKeyBase64() throws Exception {
    RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
    return Base64.getEncoder().encodeToString(publicKey.getEncoded());
}
}