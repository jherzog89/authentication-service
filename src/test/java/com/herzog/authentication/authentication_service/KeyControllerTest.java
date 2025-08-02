package com.herzog.authentication.authentication_service;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class KeyControllerTest {

    @Test
    void getPublicKey_returnsPemFormat() throws Exception {
        RSAKey rsaKey = mock(RSAKey.class);
        RSAPublicKey publicKey = mock(RSAPublicKey.class);

        byte[] encoded = "fake-public-key".getBytes();
        when(rsaKey.toRSAPublicKey()).thenReturn(publicKey);
        when(publicKey.getEncoded()).thenReturn(encoded);

        KeyController controller = new KeyController(rsaKey);
        String pem = controller.getPublicKey();

        String base64Key = Base64.getEncoder().encodeToString(encoded);
        String expectedPem = "-----BEGIN PUBLIC KEY-----\n" +
                base64Key.replaceAll("(.{64})", "$1\n") +
                "\n-----END PUBLIC KEY-----";

        assertThat(pem).isEqualTo(expectedPem);
        verify(rsaKey).toRSAPublicKey();
        verify(publicKey).getEncoded();
    }

    @Test
    void getPublicKeyBase64_returnsBase64EncodedKey() throws Exception {
        RSAKey rsaKey = mock(RSAKey.class);
        RSAPublicKey publicKey = mock(RSAPublicKey.class);

        byte[] encoded = "another-fake-key".getBytes();
        when(rsaKey.toRSAPublicKey()).thenReturn(publicKey);
        when(publicKey.getEncoded()).thenReturn(encoded);

        KeyController controller = new KeyController(rsaKey);
        String base64 = controller.getPublicKeyBase64();

        String expectedBase64 = Base64.getEncoder().encodeToString(encoded);

        assertThat(base64).isEqualTo(expectedBase64);
        verify(rsaKey).toRSAPublicKey();
        verify(publicKey).getEncoded();
    }
}