# Gerador de Senhas Seguro

Este é um gerador de senhas com interface gráfica em Python, utilizando Tkinter. O programa permite gerar senhas fortes personalizadas, salvar senhas criptografadas localmente e gerenciá-las com autenticação por senha mestre.

## Funcionalidades

- Geração de senhas com opções de incluir letras maiúsculas, minúsculas, números e símbolos.
- Avaliação visual da força da senha gerada.
- Salvar senhas com descrição e URL opcionais, criptografadas usando Fernet (AES).
- Gerenciador de senhas para visualizar, editar, excluir, adicionar e exportar senhas.
- Proteção por senha mestre com hash SHA-256.
- Copiar senhas para a área de transferência facilmente.
- Interface amigável e simples.

## Requisitos

- Python 3.6 ou superior
- Biblioteca `cryptography`
- Biblioteca `tkinter` (geralmente já incluída no Python)

## Instalação

1. Clone este repositório:
   
   ```
   git clone https://github.com/erik-vasc/gerador-de-senhas.git
   ```

2. Instale a biblioteca `cryptography`:
   
   ```
   pip install cryptography
   ```

## Como usar

1. Execute o script Python:
   
   ```
   python gerador_de_senhas.py
   ```

2. Na primeira execução, crie sua senha mestre.
3. Use a interface para gerar, copiar, salvar e gerenciar suas senhas.

## Segurança

- As senhas são armazenadas localmente em arquivo criptografado.
- A senha mestre nunca é armazenada em texto claro, apenas seu hash.
- Recomenda-se usar uma senha mestre forte e mantê-la segura.

## Desenvolvedor

Erik Vasconcelos  
Email: erikvasconcelosprogramador@gmail.com

## Licença

Este projeto está sob a licença MIT — veja o arquivo [LICENSE](LICENSE) para detalhes.