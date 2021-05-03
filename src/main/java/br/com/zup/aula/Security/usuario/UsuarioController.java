package br.com.zup.aula.Security.usuario;

import br.com.zup.aula.Security.usuario.DTOs.CadastroUsuarioDTO;
import br.com.zup.aula.Security.usuario.DTOs.UsuarioDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/usuarios")
public class UsuarioController {

    @Autowired
    private UsuarioService usuarioService;

    @PostMapping("/")
    @ResponseStatus(HttpStatus.CREATED)
    public void cadastrarUsuario(@RequestBody @Valid CadastroUsuarioDTO usuario){
        usuarioService.cadastrarNovoUsuario(usuario.converterDTOParaModel());
    }

    @GetMapping("/")
    public List<UsuarioDTO> retornarTodosOsUsuarios(){
        List<Usuario> usuarios = usuarioService.pegarTodosUsuarios();
        return UsuarioDTO.converterListaDeModelParaDTO(usuarios);
    }
}
