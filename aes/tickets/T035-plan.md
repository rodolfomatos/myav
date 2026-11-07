---
ticket: T035
title: Watcher com bloqueio automático em tempo real
sprint: research-01
priority: high
status: done
created: 2026-11-06
---

# T035 — Watcher com bloqueio automático em tempo real

## Context

O watcher atual (T007) já escaneia arquivos quando eles aparecem nos diretórios vigiados, mas é passivo: apenas detecta e coloca em quarentena. Não há bloqueio ativo nem alerta em tempo real.

O operador quer que o myav se comporte como um antivírus comercial: quando um arquivo MALICIOUS é detectado, ele deve ser colocado em quarentena imediatamente E o operador deve ser alertado em tempo real.

## Acceptance Criteria

- [x] `src/myav/watcher.py` estendido com `block_on_malicious` config option
- [x] Quando um arquivo MALICIOUS é detectado pelo watcher, ele é colocado em quarentena imediatamente (já acontece) E o operador é notificado via toast (Windows) / print (Linux)
- [x] `--watch-block` flag no CLI `myav watch` para ativar bloqueio ativo
- [x] Quando `block_on_malicious` está ativo, arquivos MALICIOUS são bloqueados: a quarentena remove o ficheiro e, se ainda existir, `chmod 000` é aplicado. O contador `blocked` é incrementado em ambos os casos.
- [x] Relatório do watcher inclui seção "Blocked" quando há bloqueios
- [x] Tests cover: watcher com block_on_malicious=True quarentena MALICIOUS, watcher com block_on_malicious=False apenas detecta, JSON output inclui bloqueados
- [x] Coverage ≥ 80% (88.63%), lint clean

## Scope

**In:** `src/myav/cli.py` (--watch-block flag), `src/myav/watcher.py` (bloqueio automático), `src/myav/config.py` (quarantine_budget_bytes já existe, adicionar block_on_malicious), tests.

**Out:** bloqueio de execução no nível do kernel (fanotify/eBPF), integração com Windows Defender, bloqueio de rede.

## Rollback

Git revert. Nada instalado ou configurado é mudado.

## Known Risks

- Bloquear arquivos pode quebrar aplicações legítimas se houver falso positivo. O operador deve revisar a quarentena.
- O watcher já escaneia após o settle window - há uma janela de vulnerabilidade entre a escrita e a detecção.
