# 🔧 HUNTEROPS-AI: IMPLEMENTATION GUIDE

**Como integrar o System Prompt no seu código Python**

---

## 1. Integração com LLM Provider (OpenAI/Anthropic)

### **Arquivo**: `hunterops/llm_integration.py` (NOVO)

```python
# hunterops/llm_integration.py

from __future__ import annotations

import os
from typing import Any
from pathlib import Path

import anthropic  # ou openai

from hunterops.runtime_paths import resolve_path


# =====================================================
# CARREGA SYSTEM PROMPT DEFINITIVO DA MEMÓRIA
# =====================================================

SYSTEM_PROMPT_PATH = "SYSTEM_PROMPT.md"


def load_system_prompt() -> str:
    """Carrega o System Prompt definitivo do projeto."""
    path = resolve_path(SYSTEM_PROMPT_PATH)
    
    if not path.exists():
        raise FileNotFoundError(
            f"System prompt não encontrado em {path}. "
            "Verifique se SYSTEM_PROMPT.md está no root do projeto."
        )
    
    return path.read_text(encoding="utf-8")


class HunterOpsAI:
    """
    Núcleo de decisão inteligente do HunterOps.
    
    Integra-se com Anthropic Claude para:
    - Validação de decisões críticas (Recon → Exploitation)
    - Triage de findings (confidence scoring)
    - Geração de rationale para debugging
    """
    
    def __init__(
        self,
        provider: str = "anthropic",  # "anthropic" ou "openai"
        model: str = "claude-3-5-sonnet-20241022",
        api_key: str | None = None,
    ):
        self.provider = provider
        self.model = model
        self.system_prompt = load_system_prompt()
        
        if provider == "anthropic":
            self.client = anthropic.Anthropic(
                api_key=api_key or os.getenv("ANTHROPIC_API_KEY")
            )
        elif provider == "openai":
            raise NotImplementedError("OpenAI provider em desenvolvimento")
        else:
            raise ValueError(f"Provider desconhecido: {provider}")
    
    def triage_finding(
        self,
        endpoint: str,
        request_data: dict[str, Any],
        response_data: dict[str, Any],
        heuristic_confidence: float,
    ) -> dict[str, Any]:
        """
        Usa LLM para validar se um POC é realmente válido.
        
        Args:
            endpoint: URL alvo (ex: https://api.target.com/v1/users)
            request_data: Payload usado no ataque
            response_data: Resposta recebida
            heuristic_confidence: Confiança calculada por heurística (0.0-1.0)
        
        Returns:
            {
                "verdict": "poc_valid" | "inconclusive" | "false_positive",
                "confidence": 0.0-1.0,
                "rationale": "2-4 sentenças técnicas expl icando a decisão"
            }
        """
        
        prompt = f"""
Você é um especialista em segurança ofensiva analisando um possível achado de vulnerabilidade.

ENDPOINT: {endpoint}
HEURÍSTICA (confiança prévia): {heuristic_confidence:.2f}

REQUEST ENVIADO:
{self._format_data(request_data)}

RESPONSE RECEBIDA:
{self._format_data(response_data)}

Com base no System Prompt HunterOps-AI, decida:

1. É um POC válido? (confidence >= 0.80 é necessário)
2. Qual é o tipo de vulnerabilidade?
3. Qual é a confiança final (0.0-1.0)?
4. Explique em 2-4 sentenças técnicas.

Responda em JSON:
{{
    "verdict": "poc_valid|inconclusive|false_positive",
    "confidence": 0.85,
    "vulnerability_type": "idor|sqli|xss|etc",
    "rationale": "Brief explanation..."
}}
"""
        
        message = self.client.messages.create(
            model=self.model,
            max_tokens=500,
            system=self.system_prompt,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        import json
        response_text = message.content[0].text
        
        try:
            result = json.loads(response_text)
            return result
        except json.JSONDecodeError:
            # Fallback se LLM não retornar JSON perfeito
            return {
                "verdict": "inconclusive",
                "confidence": heuristic_confidence * 0.8,
                "vulnerability_type": "unknown",
                "rationale": "LLM response parsing failed"
            }
    
    def should_escalate_to_exploitation(
        self,
        endpoint: str,
        technologies: list[str],
        parameters: list[str],
        priority_score: float,
    ) -> dict[str, Any]:
        """
        Decide se deve escalar de Recon para Exploitation.
        
        Retorna confiança e rationale para logging.
        """
        
        prompt = f"""
ENDPOINT: {endpoint}
TECNOLOGIAS: {', '.join(technologies)}
PARÂMETROS: {', '.join(parameters)}
PRIORITY_SCORE: {priority_score:.2f}

Baseado no System Prompt HunterOps-AI (Section 3):
- Threshold para escalação: confidence > 0.80
- Considere histórico de payouts
- Considere padrões de ataque conhecidos

Deve escalar para phase de exploitation?

Responda JSON:
{{
    "should_escalate": true|false,
    "confidence": 0.85,
    "attack_modules": ["idor_checker", "graphql_fuzz"],
    "rationale": "..."
}}
"""
        
        message = self.client.messages.create(
            model=self.model,
            max_tokens=400,
            system=self.system_prompt,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        import json
        response_text = message.content[0].text
        
        try:
            result = json.loads(response_text)
            return result
        except json.JSONDecodeError:
            return {
                "should_escalate": priority_score > 0.65,
                "confidence": priority_score * 0.7,
                "attack_modules": [],
                "rationale": "LLM response parsing failed"
            }
    
    def _format_data(self, data: dict[str, Any], max_chars: int = 1000) -> str:
        """Formata dados para exibição no prompt."""
        text = str(data)
        if len(text) > max_chars:
            return text[:max_chars] + f"\n... [+{len(text) - max_chars} chars omitidos]"
        return text


# =====================================================
# WRAPPER PARA USAR EM attack_state_machine.py
# =====================================================

_llm_instance: HunterOpsAI | None = None


def get_llm_instance() -> HunterOpsAI:
    """Singleton do LLM."""
    global _llm_instance
    if _llm_instance is None:
        _llm_instance = HunterOpsAI()
    return _llm_instance


def validate_poc_with_llm(
    endpoint: str,
    request_data: dict[str, Any],
    response_data: dict[str, Any],
    heuristic_confidence: float,
) -> tuple[str, float, str]:
    """
    Valida POC usando LLM.
    
    Retorna: (verdict, confidence, rationale)
    """
    llm = get_llm_instance()
    result = llm.triage_finding(
        endpoint=endpoint,
        request_data=request_data,
        response_data=response_data,
        heuristic_confidence=heuristic_confidence,
    )
    
    return (
        result.get("verdict", "inconclusive"),
        float(result.get("confidence", 0.5)),
        result.get("rationale", "No rationale provided"),
    )
```

---

## 2. Integração com `attack_state_machine.py`

### Modificações Necessárias

```python
# hunterops/attack_state_machine.py - MODIFICAR

from hunterops.llm_integration import validate_poc_with_llm

class PoCValidator:
    """Versão melhorada com LLM."""
    
    def validate(self, result: ModuleResult, target: Target) -> ValidationDecision:
        # Step 1: Heurística rápida
        heur = self.heuristic_check(result)
        
        # Step 2: LLM Triage (NEW)
        if heur["confidence"] > 0.50:  # Threshold mínimo
            verdict_str, llm_confidence, rationale = validate_poc_with_llm(
                endpoint=target.url,
                request_data=result.evidence.get("request", {}),
                response_data=result.evidence.get("response", {}),
                heuristic_confidence=heur["confidence"],
            )
            
            # Mapear para Verdict enum
            verdict_map = {
                "poc_valid": Verdict.POC_VALID,
                "inconclusive": Verdict.INCONCLUSIVE,
                "false_positive": Verdict.FALSE_POSITIVE,
            }
            
            final_verdict = verdict_map.get(verdict_str, Verdict.INCONCLUSIVE)
            final_confidence = llm_confidence
        else:
            final_verdict = Verdict.FALSE_POSITIVE
            final_confidence = heur["confidence"]
            rationale = heur["reason"]
        
        return ValidationDecision(
            verdict=final_verdict,
            confidence=final_confidence,
            rationale=rationale,
        )
```

---

## 3. Integração com `discord_notifier.py`

```python
# hunterops/discord_notifier.py - MODIFICAR

async def send_finding_alert(
    finding: Finding,
    confidence: float,
    rationale: str,
) -> None:
    """Envia alert de finding para Discord com estrutura definitiva."""
    
    # Mapear severidade para cor
    color_map = {
        "critical": 15158332,  # RED
        "high": 16753920,      # ORANGE
        "medium": 16776960,    # YELLOW
        "low": 3447003,        # BLUE
    }
    
    color = color_map.get(finding.severity, 3447003)
    severity_emoji = {
        "critical": "🔴",
        "high": "🟡",
        "medium": "🟠",
        "low": "🔵",
    }.get(finding.severity, "❓")
    
    embed = {
        "title": f"{severity_emoji} {finding.vulnerability_type.upper()}",
        "color": color,
        "fields": [
            {
                "name": "Program",
                "value": f"`{finding.program_id}`",
                "inline": True,
            },
            {
                "name": "Endpoint",
                "value": f"`{finding.target_url}`",
                "inline": False,
            },
            {
                "name": "Severity",
                "value": finding.severity.upper(),
                "inline": True,
            },
            {
                "name": "Confidence",
                "value": f"{confidence:.0%}",
                "inline": True,
            },
            {
                "name": "Rationale",
                "value": rationale[:500],  # MAX 500 chars
                "inline": False,
            },
            {
                "name": "Evidence",
                "value": f"[Request](link) | [Response](link) | [Screenshots](link)",
                "inline": False,
            },
        ],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    
    payload = {
        "username": "Pinguinho",
        "embeds": [embed],
    }
    
    # Se CRÍTICO: mention @channel
    if finding.severity == "critical":
        payload["content"] = "@channel ⚠️ CRITICAL FINDING"
    
    await self._dispatch_to_webhook(payload, webhook_type="findings")
```

---

## 4. Arquivo de Configuração: `hunterops_llm_config.yaml`

```yaml
# config/hunterops_llm_config.yaml (NOVO)

llm:
  enabled: true
  provider: "anthropic"  # "anthropic" ou "openai"
  model: "claude-3-5-sonnet-20241022"
  
  # Thresholds
  min_heuristic_confidence_for_llm: 0.50  # Se heurística < 0.50, skip LLM
  min_llm_confidence_required: 0.80       # Se LLM < 0.80, marcar como inconclusive
  
  # Rate limiting (para não queimar API credits)
  max_llm_calls_per_minute: 20
  max_llm_calls_per_day: 1000
  
  # Timeout
  timeout_seconds: 15
  
  # Cache (para economia)
  cache_enabled: true
  cache_ttl_seconds: 3600  # 1 hora
  
  # Fallback em caso de falha
  fallback_strategy: "heuristic"  # "heuristic" ou "conservative" (assume false_positive)

# Anthropic-specific
anthropic:
  api_key_env: "ANTHROPIC_API_KEY"
  max_tokens: 500
```

---

## 5. Environment Variable Setup

Crie um arquivo `.env` (ou configure via CI/CD):

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-v7-xxxxxxxxxxxxxxxx
HUNTEROPS_DEBUG_LLM=true  # Opcional: debug prompts
```

---

## 6. Testing: Validação do System Prompt

### **Arquivo**: `tests/test_system_prompt.py` (NOVO)

```python
# tests/test_system_prompt.py

import pytest
from hunterops.llm_integration import load_system_prompt


def test_system_prompt_loads():
    """Verifica se System Prompt carrega corretamente."""
    prompt = load_system_prompt()
    assert len(prompt) > 5000  # Deve ter tamanho razoável
    assert "Hard boundaries" in prompt or "HARD BOUNDARIES" in prompt
    assert "Rate limiting" in prompt.lower()
    assert "Discord" in prompt


def test_system_prompt_contains_critical_sections():
    """Verifica se todas as seções críticas estão presentes."""
    prompt = load_system_prompt()
    
    required_sections = [
        "scope",
        "state machine",
        "exploitation",
        "rate limit",
        "discord",
        "compliance",
    ]
    
    for section in required_sections:
        assert section.lower() in prompt.lower(), f"Seção '{section}' não encontrada"


def test_llm_triage_finding():
    """Testa LLM triage com mock."""
    from hunterops.llm_integration import HunterOpsAI
    import os
    
    if not os.getenv("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY não configurada")
    
    llm = HunterOpsAI()
    
    result = llm.triage_finding(
        endpoint="https://example.com/api/users",
        request_data={"method": "GET", "path": "/api/users/1"},
        response_data={"status": 200, "body": '{"id":1,"name":"John"}'},
        heuristic_confidence=0.65,
    )
    
    assert "verdict" in result
    assert "confidence" in result
    assert "rationale" in result
    assert 0.0 <= result["confidence"] <= 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```

---

## 7. Checklist de Implementação

- [ ] Criar `hunterops/llm_integration.py` com classe `HunterOpsAI`
- [ ] Modificar `attack_state_machine.py` para usar LLM triage
- [ ] Modificar `discord_notifier.py` para estrutura de embeds definitiva
- [ ] Criar `config/hunterops_llm_config.yaml`
- [ ] Configurar `ANTHROPIC_API_KEY` em `.env`
- [ ] Criar testes em `tests/test_system_prompt.py`
- [ ] Rodar testes: `python -m pytest tests/test_system_prompt.py -v`
- [ ] Validar carregamento: `python -c "from hunterops.llm_integration import load_system_prompt; print(len(load_system_prompt()))"`
- [ ] Review do System Prompt com stakeholders (orientador, supervisor)
- [ ] Deploy em VPS Oracle em staging
- [ ] Executar dry-run com escopo de teste
- [ ] Monitor de logs para primeira execução real

---

## 8. Documentação para seu TCC

### Seção recomendada no capítulo de Implementação:

```markdown
## 4.3 Sistema de Decisão com LLM

O núcleo inteligente do HunterOps-AI integra-se com Claude 3.5 Sonnet 
para validação de achados críticos. O System Prompt (Apêndice A) 
define:

1. **Hard Boundaries**: Validação de escopo obrigatória antes de qualquer ação
2. **State Machine**: Transições entre Recon e Exploitation baseadas em 
   confidence score > 0.80
3. **Priorização**: Algoritmo de scoring baseado em 8 fatores (asset criticality, 
   novelty, payout history, etc)
4. **Observabilidade**: Notificações Discord tipadas por severidade + audit logs

O LLM é acionado apenas quando:
- Heurística prévia >= 0.50 (confidence by pattern matching)
- Timeout < 15 segundos por call
- Rate limit: máx 20 calls/min

...
```

---

## 9. Troubleshooting

### **"ANTHROPIC_API_KEY não encontrada"**
```bash
export ANTHROPIC_API_KEY=sk-ant-...
# OU adicione em .env
```

### **"LLM response parsing failed"**
- Sistema entra em fallback automático
- Usa heurística_confidence × 0.8 como score final
- Marca como "INCONCLUSIVE" para review manual

### **"Rate limit exceeded on Anthropic API"**
- Backoff exponencial: 60s, 120s, 300s
- Depois de 3 falhas: marcar como "requires_manual_review"

---

## ✅ Próximas Etapas

1. **Implementar LLM integration** (2-3 horas)
2. **Testar com escopo pequeno** (1 programa, 5 endpoints)
3. **Validar verdicts com manual review**
4. **Ajustar thresholds conforme realidade**
5. **Documentar resultados para TCC**

À sua disposição para suporte durante implementação!
