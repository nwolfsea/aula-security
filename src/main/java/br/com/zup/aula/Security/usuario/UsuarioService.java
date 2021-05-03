package br.com.zup.aula.Security.usuario;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UsuarioService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private BCryptPasswordEncoder encoder;

    public Usuario salvarUsuario(Usuario usuario){
        return usuarioRepository.save(usuario);
    }

    public List<Usuario> pegarTodosUsuarios(){
        return (List<Usuario>) usuarioRepository.findAll();
    }

    public Usuario cadastrarNovoUsuario(Usuario usuario){
        String senhaEncoder = encoder.encode(usuario.getSenha());
        usuario.setSenha(senhaEncoder);

        return salvarUsuario(usuario);
    }
}
