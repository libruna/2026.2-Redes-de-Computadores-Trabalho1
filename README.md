# 2026.2-Redes-de-Computadores-Trabalho1
Repositório dedicado ao Trabalho 1 de Fundamentos de Redes de Computadores do 2º semestre de 2026.

## 1. Descrição

Este projeto implementa um cliente DNS em C que consulta o registro **MX (Mail Exchange)** de um domínio usando um servidor DNS informado pelo usuário. Ao interpretar uma resposta válida, o programa seleciona o registro MX com o menor valor de `preference` e imprime o domínio e o servidor escolhido.

A comunicação com o servidor DNS é feita por UDP.

## 2. Sistema operacional

- **Sistema esperado:** Linux (por exemplo, Ubuntu).
- **Também pode ser utilizado:** Ubuntu no WSL2, no Windows.
- **Windows nativo:** não é o ambiente recomendado para compilar diretamente, pois o projeto usa cabeçalhos e interfaces de rede POSIX, como `arpa/inet.h`.

## 3. Ambiente de desenvolvimento

- **Linguagem:** C.
- **Compilador:** GCC.
- **Sistema de build:** GNU Make.
- **Editor recomendado:** Visual Studio Code.
- **Terminal:** terminal Linux ou terminal da distribuição Ubuntu no WSL2.

Em sistemas baseados em Debian/Ubuntu, instale as ferramentas necessárias:

```bash
sudo apt update
sudo apt install build-essential make
```

Confira as instalações:

```bash
gcc --version
make --version
```

## 4. Organização dos arquivos

```text
.
├── Makefile
├── include/
│   ├── app_error.h
│   ├── dns_parser.h
│   ├── dns_protocol.h
│   └── udp_client.h
├── src/
│   ├── main.c
│   ├── dns_parser.c
│   ├── dns_protocol.c
│   └── udp_client.c
└── tests/
    ├── test_dns_parser.c
    └── test_dns_protocol.c
```

Responsabilidades principais:

- `src/main.c`: coordena a execução, valida os argumentos e apresenta o resultado.
- `src/dns_protocol.c`: valida o domínio, gera o Transaction ID e monta a consulta DNS MX.
- `src/udp_client.c`: gerencia a comunicação UDP com o servidor DNS.
- `src/dns_parser.c`: interpreta a resposta DNS e extrai os registros MX.
- `include/`: contém os cabeçalhos e as interfaces dos módulos.
- `tests/`: contém arquivos de teste do protocolo e do parser.

## 5. Como construir

Na raiz do projeto, execute:

```bash
make clean
make
```

`make clean` remove os arquivos de compilação anteriores e o executável gerado. `make` compila os fontes e gera o executável `meu_cliente`.

## 6. Como executar

Sintaxe:

```bash
./meu_cliente <dominio> <ipv4_dns>
```

São necessários dois argumentos:

1. `dominio`: domínio que será consultado.
2. `ipv4_dns`: endereço IPv4 do servidor DNS.

Exemplo:

```bash
./meu_cliente unb.br 8.8.8.8
```

Também é possível executar usando o alvo `run` do Makefile:

```bash
make run ARGS="unb.br 8.8.8.8"
```

## 7. Exemplos de uso

### 7.1. Sucesso

Comando:

```bash
./meu_cliente unb.br 8.8.8.8
```

Saída ilustrativa:

```text
unb.br <> unb-br.mail.protection.outlook.com
```

O programa interpretou a resposta DNS e encontrou registros MX. Ele escolhe o registro com o menor valor de `preference` e imprime o domínio e o servidor escolhido.

### 7.2. Falha 1 — domínio inexistente (`NXDOMAIN`)

Comando ilustrativo:

```bash
./meu_cliente unbaaaaa.br 8.8.8.8
```

Saída esperada se o servidor responder `NXDOMAIN`:

```text
Dominio unbaaaaa.br nao encontrado
```

O servidor DNS informou que o nome consultado não existe. O resultado depende de o servidor efetivamente retornar `NXDOMAIN`.

### 7.3. Falha 2 — domínio sem registro MX

Comando ilustrativo:

```bash
./meu_cliente sigaa.unb.br 8.8.8.8
```

Saída esperada caso o parser classifique a resposta como ausência de MX:

```text
Dominio sigaa.unb.br nao possui entrada MX
```

### 7.4. Falha 3 — servidor DNS não responde dentro do prazo

Comando ilustrativo:

```bash
./meu_cliente unb.br 100.0.0.0
```

Saída esperada se o cliente esgotar o tempo de espera sem receber resposta:

```text
Nao foi possivel coletar entrada MX para unb.br
```

## 8. Outras mensagens de erro

O programa também trata situações como:

- **Quantidade incorreta de argumentos:**

  ```text
  Uso: ./meu_cliente <dominio> <ipv4_dns>
  ```

- **Domínio inválido:**

  ```text
  Dominio invalido: ...
  ```

- **Endereço IPv4 inválido:**

  ```text
  Endereco IPv4 invalido: ...
  ```

- **Resposta DNS malformada ou erro indicado pelo servidor:**

  ```text
  Resposta DNS invalida ou erro retornado pelo servidor (...)
  ```

- **Erro interno ou de comunicação UDP:** apresenta a mensagem correspondente.

## 9. Limitações conhecidas

- O cliente consulta registros MX; não é uma ferramenta genérica para todos os tipos de registro DNS.
- A consulta é feita por UDP. Timeout e tentativas dependem da implementação em `udp_client.c`.
- O `main.c` apresentado define `DNS_PACKET_CAPACITY` como **4096 bytes** para os buffers. Se a especificação da atividade exigir **512 bytes**, ajuste essa constante e trate explicitamente respostas maiores.
- Validar o formato do IPv4 não garante que o servidor esteja acessível ou responda.
- Os resultados dependem das respostas do servidor DNS e da configuração atual dos domínios.
- O tratamento dos erros depende das classificações retornadas pelos módulos de protocolo, parser e cliente UDP.

## 10. Resumo rápido

```bash
# Compilar
make clean
make

# Consultar registros MX
./meu_cliente unb.br 8.8.8.8

# Remover executável e arquivos de compilação
make clean
```
