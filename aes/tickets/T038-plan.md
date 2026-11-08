---
ticket: T038
title: Web dashboard local (stdlib) para scans, quarentena, relatórios e intel
sprint: research-01
priority: high
status: done
created: 2026-11-07
---

# T038 — Web dashboard local (stdlib)

## Context

T034 entregou uma GUI Tkinter, mas o operador quer um dashboard acessível a partir
do browser, no mesmo modelo: **processo separado**, leitura do state DB, sem
partilhar memória com o scanner. O dashboard serve para ver o estado do produto
(scans, quarentena, relatórios, intel, regras, scheduler) sem decorar comandos.

Restrições que vêm do produto: nada de dependências novas, nada de rede externa,
nada de escrita no estado. O browser fala com um servidor local em loopback.

## Acceptance Criteria

- [x] `src/myav/research/web_dashboard.py`:
  - [x] `build_snapshot(state, paths, config, limit=50)` devolve um
        dicionário JSON-serializável e **read-only**.
  - [x] `render_html()` devolve uma página única, com CSS/JS embutidos e zero
        pedidos a CDNs.
  - [x] Servidor `ThreadingHTTPServer` com `GET`/`HEAD`:
        `/`, `/healthz`, `/api/summary`, `/api/scans`, `/api/quarantine`,
        `/api/reports`, `/api/report?name=…`, `/api/intel`.
  - [x] Apenas `GET`/`HEAD`; qualquer outro método devolve 405 com `Allow`.
  - [x] `/api/report` rejeita traversal (`../`, subdiretórios, nomes não `.md`).
- [x] `src/myav/state.py`: `recent_scans(limit)` (leitura, ordenada por id desc).
- [x] CLI `myav research web`:
  - [x] `--host` (default `127.0.0.1`), `--port` (default `8787`), `--snapshot`,
        `--open`, `--allow-remote`.
  - [x] Recusa bind não-loopback sem `--allow-remote` (exit 2).
  - [x] `--snapshot` imprime o snapshot JSON e sai (não abre socket).
- [x] Testes: snapshot com dados semeados, relatório seguro/traversal, métodos
      HTTP, endpoints principais com servidor real em porta efémera, CLI snapshot
      e recusa de host remoto.
- [x] Coverage ≥ 80%, `ruff check src tests` limpo.

## Scope

**In:** `src/myav/research/web_dashboard.py` (novo), `src/myav/state.py`,
`src/myav/cli.py`, `tests/test_web_dashboard.py`, `tests/test_cli.py`,
`tests/test_state.py`, `aes/*`, `docs/*`.

**Out:** autenticação multiuser, TLS, escrita de configuração pelo browser,
execução de scans a partir do browser, WebSocket/streaming, exposição pública,
integração com frameworks web externos.

## Design Decisions

1. **Stdlib puro.** `http.server` + `ThreadingHTTPServer`; zero dependências.
   Isto mantém a instalação igual à do CLI e da GUI.
2. **Read-only por construção.** Não há `POST`/`PUT`/`DELETE`. O pior que um
   browser local pode fazer é ler o estado que o operador já pode ler no CLI.
3. **Loopback por omissão.** Bind a `127.0.0.1`. Um host não-loopback exige
   `--allow-remote` explícito e o comando avisa que não há autenticação.
4. **Snapshot testável.** O HTML consome `/api/summary`; a mesma função
   `build_snapshot` alimenta `--snapshot`, pelo que os testes não precisam de
   browser.
5. **Traversal fechado.** Nomes de relatório são validados antes de tocar no
   filesystem: rejeita `..`, caminhos absolutos e nomes que não terminem em `.md`.

## Known Risks

- Um dashboard sem autenticação em loopback continua legível por qualquer processo
  do mesmo utilizador. É o mesmo modelo de confiança do CLI; `--allow-remote`
  torna o risco explícito.
- O snapshot lê o SQLite a cada pedido. O volume é baixo (dashboard humano) e as
  conexões são curtas, como no resto do produto.
- O HTML embutido é estático; se o JavaScript falhar ou o pedido `/api/*`
  falhar, as tabelas ficam vazias (a página base continua visível).
