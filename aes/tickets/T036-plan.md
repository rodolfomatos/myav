---
ticket: T036
title: Sandbox comportamental completo (syscalls, ransomware, evasão)
sprint: research-01
priority: high
status: done
created: 2026-11-07
---

# T036 — Sandbox comportamental completo (syscalls, ransomware, evasão)

## Context

T031 entregou um sandbox leve baseado em polling: observa spawns, modificações de
ficheiros, autostart e indicadores de evasão, mas não vê **syscalls**. Sem syscalls
não é possível distinguir um ficheiro copiado de um ficheiro cifrado, nem detetar
padrões de ransomware (milhares de `write`/`rename`/`unlink` numa janela curta) ou
evasão anti-depuração (`ptrace`, `fork` em massa).

T036 estende o sandbox existente — não cria um segundo sandbox. A execução continua
opt-in, read-only e nunca bloqueia. Nada aqui é Core protection.

## Acceptance Criteria

- [x] Novo módulo `src/myav/research/syscall_monitor.py` com:
  - [x] `strace_available()` e `build_strace_command()` (opt-in; degrada para o
        sandbox de polling quando `strace` não existe).
  - [x] `parse_strace_log(text) -> SyscallSummary` — conta syscalls e identifica
        escritas de ficheiros, renames, unlinks, `execve` e `connect`.
  - [x] `detect_mass_encryption(summary, thresholds)` — alerta quando o número de
        ficheiros escritos/renomeados/apagados numa janela curta excede o limiar.
  - [x] `detect_syscall_evasion(summary)` — alerta para `ptrace` (anti-debug),
        número anómalo de `fork`/`clone`, e auto-eliminação.
- [x] `src/myav/research/sandbox.py`:
  - [x] `SandboxResult.syscalls` e `SandboxResult.findings`.
  - [x] `run_in_sandbox(..., use_syscalls: bool = False)` executa sob `strace`
        quando disponível e pedido; caso contrário mantém o comportamento T031.
  - [x] Resultado JSON inclui `syscalls` e `findings`.
- [x] CLI `myav research sandbox <file> [--duration N] [--syscalls] [--json]`.
- [x] Deteção de ransomware por encriptação em massa ligada ao relatório do sandbox
      (não ao watcher; nada é bloqueado).
- [x] Testes unitários para parser, mass-encryption, evasão e CLI; testes de
      execução real só correm se `strace` estiver disponível e funcional.
- [x] Coverage ≥ 80%, `ruff check src tests` limpo.

## Scope

**In:** `src/myav/research/syscall_monitor.py` (novo), `src/myav/research/sandbox.py`,
`src/myav/cli.py`, `tests/test_syscall_monitor.py`, `tests/test_sandbox.py`,
`tests/test_cli.py`, `aes/*`.

**Out:** bloqueio em tempo real (pertence ao watcher/T035), fanotify/eBPF, execução
de amostras reais, integração com rede/VT, promoção a Core protection.

## Design Decisions

1. **strace é opcional.** O sandbox funciona sem ele; `--syscalls` apenas enriquece
   a observação. Isto mantém o produto offline e portátil.
2. **Parser puro e testável.** `parse_strace_log` recebe texto, não executa nada —
   os testes cobrem o formato real do `strace -f -e trace=...` sem depender do kernel.
3. **Limiares explícitos.** Mass-encryption usa contagens configuráveis (por omissão
   ≥ 20 escritas ou ≥ 10 renames ou ≥ 10 unlinks na janela), documentadas e testadas.
4. **Sem veredicto.** Findings são alertas de research; o sandbox nunca quarentena
   nem altera o alvo.

## Known Risks

- `strace` pode falhar em ambientes com `ptrace_scope` restrito; o código degrada e
  regista a razão em vez de rebentar.
- Um processo pode escrever muitos ficheiros legítimos (compiladores, instaladores);
  por isso o finding é `medium`/`high` e sempre acompanhado da contagem observada.
- Executar amostras reais continua a ser responsabilidade do operador; os testes
  usam apenas scripts inócuos ou texto sintético.
