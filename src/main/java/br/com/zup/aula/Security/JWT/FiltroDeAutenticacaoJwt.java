package br.com.zup.aula.Security.JWT;

import br.com.zup.aula.Security.usuario.DTOs.LoginDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class FiltroDeAutenticacaoJwt extends UsernamePasswordAuthenticationFilter {


    private ComponenteJWT componenteJWT;
    private AuthenticationManager authenticationManager;

    @Autowired
    public FiltroDeAutenticacaoJwt(ComponenteJWT componenteJWT, AuthenticationManager authenticationManager) {
        this.componenteJWT = componenteJWT;
        this.authenticationManager = authenticationManager;
    }

    public FiltroDeAutenticacaoJwt(AuthenticationManager authenticationManager, ComponenteJWT componenteJWT, AuthenticationManager authenticationManager1) {
        this.componenteJWT = componenteJWT;
        this.authenticationManager = authenticationManager1;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        ObjectMapper objectMapper = new ObjectMapper();
        try {
            LoginDTO login = objectMapper.readValue(request.getInputStream(), LoginDTO.class);
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(login.getEmail(), login.getSenha(), new ArrayList<>());

            Authentication auth = authenticationManager.authenticate(authToken);

            return auth;
        } catch (IOException error) {
            throw new RuntimeException(error.getMessage());
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        String username = ((UsuarioLogin)authResult.getPrincipal()).getUsername();
        String token = componenteJWT.gerarToken(username);

        response.addHeader("Authorization", "Token " +token);
    }
}

