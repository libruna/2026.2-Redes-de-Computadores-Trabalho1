# Convenções do projeto

## Branches

Formato: `tipo/numero-da-issue-descricao-curta`

```
feat/4-qname-qtype-qclass
fix/6-datagrama-truncado
docs/20-readme
```

- Uma branch por issue, criada a partir da `main` atualizada.
- Descrição em minúsculas, sem acentos, com hífens.

## Commits

Formato: `tipo: descrição curta`

```
feat: adiciona leitura de nomes com compressão
fix: rejeita ponteiro de compressão cíclico
docs: adiciona instruções de execução
```

| Tipo | Uso |
|---|---|
| `feat` | Nova funcionalidade |
| `fix` | Correção de erro |
| `docs` | README e documentação |
| `build` | Makefile, compilação e pipeline |
| `refactor` | Mudança de código sem alterar comportamento |

- Descrição em português, no presente (`adiciona`, `corrige`, `valida`), sem ponto final.
- Commits pequenos, um assunto por commit.

## Pull requests

- Um PR por issue, com `Closes #N` na descrição.
- Antes de abrir: código compilando sem avisos.
- Ninguém faz push direto na `main`.
