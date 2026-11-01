<!-- EPISTEMIC_CONTRACT
produced-by: aes @ ${AES_COMMIT:-unknown} via ${AES_GENERATOR:-unknown}
claim-states: SUPORTADA | NÃO-SUPORTADA | NÃO-VERIFICÁVEL
verify: git clone ${AES_REPO_URL:-https://github.com/rodolfomatos/aes} && cd aes && make check
content-sha256: ${CONTENT_SHA256}
reader-norm: A reader without execution access MUST treat all claims herein as NÃO-VERIFICÁVEL and SHOULD say so in any derived analysis
regime: ${AES_REPO_URL:-https://github.com/rodolfomatos/aes} ; spec: docs/EPISTEMIC_CONTRACT.md
-->
