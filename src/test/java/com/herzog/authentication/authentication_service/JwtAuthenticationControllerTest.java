package com.herzog.authentication.authentication_service;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class JwtAuthenticationControllerTest {

    @SuppressWarnings("null")
    @Test
    void generateToken_returnsJwtTokenResponse() {
        // Arrange
        JwtTokenService tokenService = mock(JwtTokenService.class);
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        JwtAuthenticationController controller = new JwtAuthenticationController(tokenService, authenticationManager);

        JwtTokenRequest request = mock(JwtTokenRequest.class);
        when(request.username()).thenReturn("jason");
        when(request.password()).thenReturn("dummy");

        Authentication authentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(tokenService.generateToken(authentication)).thenReturn("token");

        // Act
        ResponseEntity<JwtTokenResponse> response = controller.generateToken(request);

        // Assert
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().token()).isEqualTo("token");

        // Verify authenticationManager called with correct token
        ArgumentCaptor<UsernamePasswordAuthenticationToken> captor = ArgumentCaptor.forClass(UsernamePasswordAuthenticationToken.class);
        verify(authenticationManager).authenticate(captor.capture());
        UsernamePasswordAuthenticationToken token = captor.getValue();
        assertThat(token.getPrincipal()).isEqualTo("jason");
        assertThat(token.getCredentials()).isEqualTo("dummy");

        verify(tokenService).generateToken(authentication);
    }
}