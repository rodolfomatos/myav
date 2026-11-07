---
ticket: T037
title: Threat-intel feeds (Abuse.ch / MISP) com cache offline
sprint: research-01
priority: high
status: done
created: 2026-11-07
---

# T037 — Threat-intel feeds (Abuse.ch / MISP) com cache offline

## Context

myav já consulta o VirusTotal por hash (opt-in). Falta uma fonte de reputação
local, offline e determinística: hashes/URLs/domínios maliciosos descarregados
de feeds públicos (Abuse.ch URLhaus, MalwareBazaar, ThreatFox) ou de uma
instância MISP, guardados numa cache SQLite e consultáveis sem rede.

O objetivo não é substituir o ClamAV. É dar ao operador uma segunda opinião
exata e explicável, com cache que funciona offline depois do primeiro update.

## Acceptance Criteria

- [x] `src/myav/intel.py`:
  - [x] `IntelIOC` + normalização (sha256 | url | domain | ip).
  - [x] Parsers puros: `urlhaus-csv`, `malwarebazaar-json`, `threatfox-json`,
        `misp-json`, `text`.
  - [x] `update_from_source(state, name, source, fmt, get=...)` — fonte pode ser
        URL ou ficheiro local; sem rede nos testes.
  - [x] `fetch_text()` injectável (mesmo padrão do VirusTotal).
- [x] `src/myav/state.py`:
  - [x] Tabelas `intel_iocs` (PK `type+value+source`) e `intel_feeds`.
  - [x] Métodos `upsert_intel`, `lookup_intel`, `intel_summary`, `intel_feeds`,
        `clear_intel`.
- [x] `src/myav/engines/intel_engine.py`:
  - [x] `IntelEngine.lookup(sha256)` → `MALICIOUS` em correspondência exata,
        com fonte no `signature`/`detail`; `CLEAN` caso contrário.
  - [x] Só entra no pipeline quando `[intel].enabled = true` e existe cache.
- [x] `src/myav/config.py`: `IntelConfig(enabled=False, max_age_hours=168, timeout=20)`.
- [x] `src/myav/pipeline.py`: `Engines.intel` opcional; `scan_file` consulta-o.
- [x] CLI `myav intel`:
  - [x] `update --name <label> --source <url|path> [--format auto|...]`
  - [x] `import <path> --name <label> [--format ...]`
  - [x] `check <indicator> [--json]` (exit 0 encontrado, 1 não encontrado)
  - [x] `status [--json]`
  - [x] `clear --yes`
- [x] Testes: parsers, normalização, engine, pipeline, CLI; tudo com dados
      sintéticos e sem rede.
- [x] Coverage ≥ 80%, `ruff check src tests` limpo.

## Scope

**In:** `src/myav/intel.py`, `src/myav/engines/intel_engine.py`,
`src/myav/state.py`, `src/myav/config.py`, `src/myav/pipeline.py`,
`src/myav/cli.py`, tests, docs.

**Out:** atualização automática em background, chamadas de rede no scan,
bloqueio por URL/domínio no watcher, MISP write-back, feeds pagos, promoção a
Core protection sem medição.

## Design Decisions

1. **Exato, não heurístico.** O engine só dispara em `sha256` exato. URLs e
   domínios ficam disponíveis em `intel check` mas não alteram veredictos de
   ficheiros nesta iteracão — evita falsos positivos por strings embutidas.
2. **Cache primeiro.** `update`/`import` escrevem na DB; `scan` nunca faz rede.
   Isto mantém o produto offline e o scan rápido.
3. **Confiança explícita.** Cada IOC transporta `source` e `confidence`; o
   relatório mostra a fonte, nunca "threat intel" anónimo.
4. **Sem segredos novos.** MISP é importado a partir de um export JSON local ou
   URL fornecida pelo operador; a chave não é guardada nesta iteracão.

## Known Risks

- Feeds públicos contêm falsos positivos e IOCs antigos. Mitigação: cache com
  `max_age_hours`, fonte visível, e apenas hashes alteram veredictos.
- Quem controla o feed controla a deteção; por isso o update é manual/opt-in.
- `intel check` de URL/domínio pode ser enganado por lookalikes; é advisory.
