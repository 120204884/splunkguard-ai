import os, re, time, logging, smtplib, uvicorn, json, threading, httpx
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from io import StringIO

from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator
from supabase import create_client, Client

# ─── CONFIGURACIÓN ────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

SUPABASE_URL        = os.getenv("SUPABASE_URL")
SUPABASE_KEY        = os.getenv("SUPABASE_KEY")
SPLUNK_HEC_URL      = os.getenv("SPLUNK_HEC_URL", "https://splunk:8088/services/collector/event")
SPLUNK_HEC_TOKEN    = os.getenv("SPLUNK_HEC_TOKEN", "")
SPLUNK_API_URL      = os.getenv("SPLUNK_API_URL", "https://splunk:8089")
SPLUNK_USER         = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASS         = os.getenv("SPLUNK_PASS", "")
ANTHROPIC_API_KEY   = os.getenv("ANTHROPIC_API_KEY", "")
EMAIL_ADDRESS       = os.getenv("EMAIL_ADDRESS", "")
EMAIL_PASSWORD      = os.getenv("EMAIL_PASSWORD", "")
SLACK_WEBHOOK_URL   = os.getenv("SLACK_WEBHOOK_URL", "")
CRON_SECRET         = os.getenv("CRON_SECRET", "change-me")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Faltan SUPABASE_URL o SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ─── I18N — 10 IDIOMAS ────────────────────────────────────────────────────────
TRANSLATIONS = {
    "es": {
        "alert_cpu":        "⚠️ CPU alta detectada en {host}: {value}%",
        "alert_memory":     "⚠️ Memoria alta en {host}: {value}%",
        "alert_security":   "🔒 Actividad sospechosa desde IP {ip}: {count} intentos",
        "alert_anomaly":    "🔍 Anomalía detectada: {desc}",
        "incident_created": "🚨 Incidente #{id} creado: {title}",
        "remediation_done": "✅ Auto-remediación aplicada en {host}: {action}",
        "report_subject":   "📊 Reporte semanal SplunkGuard AI",
        "risk_score":       "Score de riesgo global: {score}/100",
        "prediction":       "Predicción: {host} podría fallar en {hours}h ({prob}%)",
        "welcome":          "Bienvenido a SplunkGuard AI",
    },
    "en": {
        "alert_cpu":        "⚠️ High CPU detected on {host}: {value}%",
        "alert_memory":     "⚠️ High memory on {host}: {value}%",
        "alert_security":   "🔒 Suspicious activity from IP {ip}: {count} attempts",
        "alert_anomaly":    "🔍 Anomaly detected: {desc}",
        "incident_created": "🚨 Incident #{id} created: {title}",
        "remediation_done": "✅ Auto-remediation applied on {host}: {action}",
        "report_subject":   "📊 SplunkGuard AI Weekly Report",
        "risk_score":       "Global risk score: {score}/100",
        "prediction":       "Prediction: {host} may fail in {hours}h ({prob}%)",
        "welcome":          "Welcome to SplunkGuard AI",
    },
    "pt": {
        "alert_cpu":        "⚠️ CPU alta detectada em {host}: {value}%",
        "alert_memory":     "⚠️ Memória alta em {host}: {value}%",
        "alert_security":   "🔒 Atividade suspeita do IP {ip}: {count} tentativas",
        "alert_anomaly":    "🔍 Anomalia detectada: {desc}",
        "incident_created": "🚨 Incidente #{id} criado: {title}",
        "remediation_done": "✅ Auto-remediação aplicada em {host}: {action}",
        "report_subject":   "📊 Relatório semanal SplunkGuard AI",
        "risk_score":       "Pontuação de risco global: {score}/100",
        "prediction":       "Previsão: {host} pode falhar em {hours}h ({prob}%)",
        "welcome":          "Bem-vindo ao SplunkGuard AI",
    },
    "fr": {
        "alert_cpu":        "⚠️ CPU élevé détecté sur {host}: {value}%",
        "alert_memory":     "⚠️ Mémoire élevée sur {host}: {value}%",
        "alert_security":   "🔒 Activité suspecte depuis IP {ip}: {count} tentatives",
        "alert_anomaly":    "🔍 Anomalie détectée: {desc}",
        "incident_created": "🚨 Incident #{id} créé: {title}",
        "remediation_done": "✅ Auto-remédiation appliquée sur {host}: {action}",
        "report_subject":   "📊 Rapport hebdomadaire SplunkGuard AI",
        "risk_score":       "Score de risque global: {score}/100",
        "prediction":       "Prédiction: {host} pourrait tomber en panne dans {hours}h ({prob}%)",
        "welcome":          "Bienvenue sur SplunkGuard AI",
    },
    "de": {
        "alert_cpu":        "⚠️ Hohe CPU auf {host}: {value}%",
        "alert_memory":     "⚠️ Hoher Speicher auf {host}: {value}%",
        "alert_security":   "🔒 Verdächtige Aktivität von IP {ip}: {count} Versuche",
        "alert_anomaly":    "🔍 Anomalie erkannt: {desc}",
        "incident_created": "🚨 Vorfall #{id} erstellt: {title}",
        "remediation_done": "✅ Auto-Remediation auf {host}: {action}",
        "report_subject":   "📊 SplunkGuard AI Wochenbericht",
        "risk_score":       "Globaler Risikoscore: {score}/100",
        "prediction":       "Vorhersage: {host} könnte in {hours}h ausfallen ({prob}%)",
        "welcome":          "Willkommen bei SplunkGuard AI",
    },
    "it": {
        "alert_cpu":        "⚠️ CPU alta su {host}: {value}%",
        "alert_memory":     "⚠️ Memoria alta su {host}: {value}%",
        "alert_security":   "🔒 Attività sospetta dall'IP {ip}: {count} tentativi",
        "alert_anomaly":    "🔍 Anomalia rilevata: {desc}",
        "incident_created": "🚨 Incidente #{id} creato: {title}",
        "remediation_done": "✅ Auto-rimedio applicato su {host}: {action}",
        "report_subject":   "📊 Report settimanale SplunkGuard AI",
        "risk_score":       "Punteggio di rischio globale: {score}/100",
        "prediction":       "Previsione: {host} potrebbe fallire in {hours}h ({prob}%)",
        "welcome":          "Benvenuto in SplunkGuard AI",
    },
    "zh": {
        "alert_cpu":        "⚠️ {host} CPU 过高: {value}%",
        "alert_memory":     "⚠️ {host} 内存过高: {value}%",
        "alert_security":   "🔒 来自 IP {ip} 的可疑活动: {count} 次尝试",
        "alert_anomaly":    "🔍 检测到异常: {desc}",
        "incident_created": "🚨 事件 #{id} 已创建: {title}",
        "remediation_done": "✅ 已在 {host} 应用自动修复: {action}",
        "report_subject":   "📊 SplunkGuard AI 每周报告",
        "risk_score":       "全球风险评分: {score}/100",
        "prediction":       "预测: {host} 可能在 {hours}h 内发生故障 ({prob}%)",
        "welcome":          "欢迎使用 SplunkGuard AI",
    },
    "ja": {
        "alert_cpu":        "⚠️ {host} でCPU高負荷: {value}%",
        "alert_memory":     "⚠️ {host} でメモリ高負荷: {value}%",
        "alert_security":   "🔒 IP {ip} からの不審なアクティビティ: {count} 回の試行",
        "alert_anomaly":    "🔍 異常を検出: {desc}",
        "incident_created": "🚨 インシデント #{id} 作成: {title}",
        "remediation_done": "✅ {host} で自動修復を適用: {action}",
        "report_subject":   "📊 SplunkGuard AI 週次レポート",
        "risk_score":       "グローバルリスクスコア: {score}/100",
        "prediction":       "予測: {host} は {hours}h 以内に障害が発生する可能性 ({prob}%)",
        "welcome":          "SplunkGuard AI へようこそ",
    },
    "ar": {
        "alert_cpu":        "⚠️ وحدة المعالجة المركزية عالية على {host}: {value}%",
        "alert_memory":     "⚠️ ذاكرة عالية على {host}: {value}%",
        "alert_security":   "🔒 نشاط مشبوه من IP {ip}: {count} محاولة",
        "alert_anomaly":    "🔍 تم اكتشاف شذوذ: {desc}",
        "incident_created": "🚨 تم إنشاء الحادث #{id}: {title}",
        "remediation_done": "✅ تم تطبيق المعالجة التلقائية على {host}: {action}",
        "report_subject":   "📊 تقرير SplunkGuard AI الأسبوعي",
        "risk_score":       "درجة المخاطر العالمية: {score}/100",
        "prediction":       "تنبؤ: قد يفشل {host} في {hours}h ({prob}%)",
        "welcome":          "مرحبًا بك في SplunkGuard AI",
    },
    "ru": {
        "alert_cpu":        "⚠️ Высокий CPU на {host}: {value}%",
        "alert_memory":     "⚠️ Высокая память на {host}: {value}%",
        "alert_security":   "🔒 Подозрительная активность с IP {ip}: {count} попыток",
        "alert_anomaly":    "🔍 Обнаружена аномалия: {desc}",
        "incident_created": "🚨 Инцидент #{id} создан: {title}",
        "remediation_done": "✅ Авто-исправление применено на {host}: {action}",
        "report_subject":   "📊 Еженедельный отчёт SplunkGuard AI",
        "risk_score":       "Глобальный рейтинг риска: {score}/100",
        "prediction":       "Прогноз: {host} может выйти из строя через {hours}ч ({prob}%)",
        "welcome":          "Добро пожаловать в SplunkGuard AI",
    },
}

def t(lang: str, key: str, **kwargs) -> str:
    lang = lang if lang in TRANSLATIONS else "en"
    msg = TRANSLATIONS[lang].get(key, TRANSLATIONS["en"].get(key, key))
    try:
        return msg.format(**kwargs)
    except Exception:
        return msg

# ─── SPLUNK CLIENT ────────────────────────────────────────────────────────────
class SplunkClient:
    def __init__(self):
        self.hec_url   = SPLUNK_HEC_URL
        self.hec_token = SPLUNK_HEC_TOKEN
        self.api_url   = SPLUNK_API_URL
        self.user      = SPLUNK_USER
        self.password  = SPLUNK_PASS

    def send_event(self, event: dict, sourcetype: str = "splunkguard:event") -> bool:
        if not self.hec_token:
            logger.warning("Splunk HEC token no configurado — evento simulado")
            logger.info(f"[SPLUNK MOCK] {sourcetype}: {json.dumps(event)}")
            return True
        try:
            payload = {"event": event, "sourcetype": sourcetype, "time": time.time()}
            with httpx.Client(verify=False, timeout=5) as client:
                r = client.post(
                    self.hec_url,
                    headers={"Authorization": f"Splunk {self.hec_token}"},
                    json=payload
                )
            return r.status_code == 200
        except Exception as e:
            logger.error(f"Splunk HEC error: {e}")
            return False

    def search(self, query: str, earliest: str = "-1h") -> list:
        if not self.password:
            logger.warning("Splunk API no configurada — búsqueda simulada")
            return []
        try:
            with httpx.Client(verify=False, timeout=30) as client:
                r = client.post(
                    f"{self.api_url}/services/search/jobs/export",
                    auth=(self.user, self.password),
                    data={"search": f"search {query}", "earliest_time": earliest,
                          "latest_time": "now", "output_mode": "json"}
                )
            return [json.loads(line) for line in r.text.strip().split("\n") if line]
        except Exception as e:
            logger.error(f"Splunk Search error: {e}")
            return []

splunk = SplunkClient()

# ─── AI AGENT (ANTHROPIC) ─────────────────────────────────────────────────────
async def ai_analyze(prompt: str, context: dict = {}) -> str:
    if not ANTHROPIC_API_KEY:
        return "IA no configurada. Configura ANTHROPIC_API_KEY."
    try:
        system = (
            "Eres SplunkGuard AI, un agente experto en seguridad, observabilidad y operaciones IT. "
            "Analiza los datos proporcionados y da respuestas concretas, accionables y en el idioma del usuario. "
            "Siempre incluye: 1) Qué detectaste, 2) Por qué es importante, 3) Qué acción tomar."
        )
        messages = [{"role": "user", "content": f"Contexto: {json.dumps(context)}\n\nPregunta: {prompt}"}]
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": "claude-sonnet-4-20250514", "max_tokens": 1000,
                      "system": system, "messages": messages}
            )
        data = r.json()
        return data["content"][0]["text"] if data.get("content") else "Sin respuesta."
    except Exception as e:
        logger.error(f"AI error: {e}")
        return f"Error al consultar IA: {str(e)}"

# ─── MOTOR DE CORRELACIÓN ─────────────────────────────────────────────────────
def correlate_events(metrics: list, security_events: list) -> dict:
    score = 0
    alerts = []

    cpu_high     = [m for m in metrics      if m.get("cpu", 0) > 85]
    mem_high     = [m for m in metrics      if m.get("memory", 0) > 90]
    brute_force  = [s for s in security_events if s.get("type") == "brute_force"]
    unknown_ips  = [s for s in security_events if s.get("type") == "unknown_ip"]

    if cpu_high:    score += 20 * len(cpu_high)
    if mem_high:    score += 15 * len(mem_high)
    if brute_force: score += 30 * len(brute_force)
    if unknown_ips: score += 10 * len(unknown_ips)

    # Correlación cruzada — posible ataque en curso
    if brute_force and cpu_high:
        score += 25
        alerts.append({"severity": "CRITICAL", "message":
            "Posible ataque activo: fuerza bruta + CPU alta simultáneos"})

    if unknown_ips and mem_high:
        score += 20
        alerts.append({"severity": "HIGH", "message":
            "IP desconocida + memoria alta: posible exfiltración de datos"})

    return {
        "risk_score":    min(score, 100),
        "level":         "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW",
        "correlated_alerts": alerts,
        "timestamp":     datetime.now().isoformat()
    }

# ─── PREDICCIÓN ML SIMPLE ─────────────────────────────────────────────────────
def predict_failure(host: str, history: list) -> dict:
    if len(history) < 3:
        return {"prediction": False, "probability": 0, "hours": None}
    values = [h.get("cpu", 0) for h in history[-10:]]
    if len(values) < 2:
        return {"prediction": False, "probability": 0, "hours": None}
    trend = (values[-1] - values[0]) / len(values)
    if trend > 2:
        hours_to_fail = max(1, int((100 - values[-1]) / trend))
        prob = min(95, int(trend * 15))
        return {"prediction": True, "probability": prob,
                "hours": hours_to_fail, "host": host,
                "current_cpu": values[-1], "trend": round(trend, 2)}
    return {"prediction": False, "probability": int(trend * 5), "hours": None}

# ─── AUTO-REMEDIACIÓN ─────────────────────────────────────────────────────────
def auto_remediate(issue_type: str, host: str, lang: str = "es") -> dict:
    actions = {
        "high_cpu":    {"action": "restart_service", "command": f"systemctl restart app@{host}", "description": "Reiniciar servicio"},
        "high_memory": {"action": "clear_cache",     "command": f"sync && echo 3 > /proc/sys/vm/drop_caches", "description": "Limpiar caché"},
        "brute_force": {"action": "block_ip",        "command": f"iptables -A INPUT -s {{ip}} -j DROP", "description": "Bloquear IP"},
        "disk_full":   {"action": "clean_logs",      "command": f"find /var/log -name '*.log' -mtime +7 -delete", "description": "Limpiar logs"},
    }
    remedy = actions.get(issue_type, {"action": "alert_only", "command": "", "description": "Solo alerta"})
    logger.info(f"AUTO-REMEDIATION [{host}]: {remedy['action']}")
    splunk.send_event({
        "type": "remediation", "host": host,
        "action": remedy["action"], "issue": issue_type,
        "timestamp": datetime.now().isoformat()
    }, sourcetype="splunkguard:remediation")
    return {
        "applied": True, "host": host,
        "action": remedy["action"],
        "description": t(lang, "remediation_done", host=host, action=remedy["description"]),
        "timestamp": datetime.now().isoformat()
    }

# ─── EMAIL + SLACK ─────────────────────────────────────────────────────────────
def send_email(to: str, subject: str, body: str) -> bool:
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        return False
    for attempt in range(2):
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"]    = EMAIL_ADDRESS
            msg["To"]      = to
            msg.attach(MIMEText(body, "html"))
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
                s.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
                s.send_message(msg)
            return True
        except Exception as e:
            logger.error(f"Email error intento {attempt+1}: {e}")
            time.sleep(1)
    return False

def send_slack(message: str) -> bool:
    if not SLACK_WEBHOOK_URL:
        return False
    try:
        with httpx.Client(timeout=5) as client:
            r = client.post(SLACK_WEBHOOK_URL, json={"text": message})
        return r.status_code == 200
    except Exception as e:
        logger.error(f"Slack error: {e}")
        return False

def notify_all(message: str, email_to: str = "", subject: str = "SplunkGuard Alert"):
    if email_to:
        send_email(email_to, subject, f"<p>{message}</p>")
    send_slack(message)

# ─── CRON — MONITOREO AUTOMÁTICO ─────────────────────────────────────────────
def _cron_monitor():
    while True:
        time.sleep(300)  # cada 5 minutos
        try:
            logger.info("CRON: Ejecutando monitoreo automático...")
            orgs = supabase.table("organizations").select("id, nombre, lang").execute()
            for org in (orgs.data or []):
                try:
                    lang   = org.get("lang", "en")
                    org_id = org["id"]
                    metrics = supabase.table("metrics").select("*").eq("org_id", org_id)\
                        .order("created_at", desc=True).limit(20).execute().data or []
                    sec_events = supabase.table("security_events").select("*").eq("org_id", org_id)\
                        .gte("created_at", (datetime.now() - timedelta(hours=1)).isoformat()).execute().data or []
                    correlation = correlate_events(metrics, sec_events)
                    supabase.table("risk_scores").upsert({
                        "org_id": org_id, "score": correlation["risk_score"],
                        "level": correlation["level"], "updated_at": datetime.now().isoformat()
                    }).execute()
                    if correlation["risk_score"] >= 50:
                        msg = t(lang, "risk_score", score=correlation["risk_score"])
                        admins = supabase.table("org_members").select("user_id").eq("org_id", org_id)\
                            .eq("role", "admin").execute().data or []
                        for admin in admins:
                            try:
                                u = supabase.auth.admin.get_user_by_id(admin["user_id"])
                                if u and u.user and u.user.email:
                                    notify_all(msg, email_to=u.user.email,
                                               subject=f"🚨 SplunkGuard AI — Riesgo {correlation['level']}")
                            except Exception as e:
                                logger.error(f"CRON notify error: {e}")
                    # Auto-remediación
                    for m in metrics[:3]:
                        if m.get("cpu", 0) > 90:
                            auto_remediate("high_cpu", m.get("host", "unknown"), lang)
                        if m.get("memory", 0) > 95:
                            auto_remediate("high_memory", m.get("host", "unknown"), lang)
                    for s in sec_events:
                        if s.get("type") == "brute_force":
                            auto_remediate("brute_force", s.get("host", "unknown"), lang)
                    # Predicción
                    hosts = list({m.get("host") for m in metrics if m.get("host")})
                    for host in hosts:
                        host_history = [m for m in metrics if m.get("host") == host]
                        pred = predict_failure(host, host_history)
                        if pred["prediction"] and pred["probability"] > 60:
                            supabase.table("predictions").upsert({
                                "org_id": org_id, "host": host,
                                "probability": pred["probability"],
                                "hours": pred["hours"],
                                "updated_at": datetime.now().isoformat()
                            }).execute()
                            msg = t(lang, "prediction", host=host,
                                    hours=pred["hours"], prob=pred["probability"])
                            logger.warning(f"PREDICTION: {msg}")
                except Exception as e:
                    logger.error(f"CRON org error {org['id']}: {e}")
            logger.info("CRON: Ciclo completado.")
        except Exception as e:
            logger.error(f"CRON general error: {e}")

def _cron_weekly_report():
    while True:
        time.sleep(604800)  # 7 días
        try:
            logger.info("CRON: Generando reportes semanales...")
            orgs = supabase.table("organizations").select("id, nombre, lang").execute()
            for org in (orgs.data or []):
                lang   = org.get("lang", "en")
                org_id = org["id"]
                incidents = supabase.table("incidents").select("*").eq("org_id", org_id)\
                    .gte("created_at", (datetime.now() - timedelta(days=7)).isoformat()).execute().data or []
                resolved  = [i for i in incidents if i.get("status") == "resolved"]
                avg_resolution = 0
                if resolved:
                    times = []
                    for inc in resolved:
                        try:
                            c = datetime.fromisoformat(inc["created_at"])
                            r = datetime.fromisoformat(inc["resolved_at"])
                            times.append((r - c).seconds / 60)
                        except Exception:
                            pass
                    avg_resolution = round(sum(times) / len(times), 1) if times else 0
                html = f"""
                <html><body style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
                <h1 style="color:#1e293b">📊 {t(lang,'report_subject')}</h1>
                <h2>{org['nombre']}</h2>
                <table style="width:100%;border-collapse:collapse">
                  <tr style="background:#f1f5f9"><td style="padding:12px"><b>Total incidentes</b></td><td>{len(incidents)}</td></tr>
                  <tr><td style="padding:12px"><b>Resueltos</b></td><td>{len(resolved)}</td></tr>
                  <tr style="background:#f1f5f9"><td style="padding:12px"><b>Tiempo prom. resolución</b></td><td>{avg_resolution} min</td></tr>
                  <tr><td style="padding:12px"><b>Tasa de resolución</b></td><td>{round(len(resolved)/max(len(incidents),1)*100)}%</td></tr>
                </table>
                <p style="color:#64748b;font-size:12px">SplunkGuard AI — Reporte automático</p>
                </body></html>"""
                admins = supabase.table("org_members").select("user_id").eq("org_id", org_id)\
                    .eq("role", "admin").execute().data or []
                for admin in admins:
                    try:
                        u = supabase.auth.admin.get_user_by_id(admin["user_id"])
                        if u and u.user and u.user.email:
                            send_email(u.user.email, t(lang, "report_subject"), html)
                    except Exception as e:
                        logger.error(f"Report email error: {e}")
        except Exception as e:
            logger.error(f"CRON weekly report error: {e}")

threading.Thread(target=_cron_monitor,      daemon=True).start()
threading.Thread(target=_cron_weekly_report, daemon=True).start()
logger.info("CRONs iniciados: monitoreo cada 5min + reporte semanal")

# ─── RATE LIMITER ──────────────────────────────────────────────────────────────
_req_counts    = defaultdict(list)
_login_fails   = defaultdict(list)

def rate_limit(ip: str, max_req: int = 60, window: int = 60):
    now = time.time()
    _req_counts[ip] = [t for t in _req_counts[ip] if now - t < window]
    if len(_req_counts[ip]) >= max_req:
        raise HTTPException(429, "Demasiadas peticiones. Espera un momento.")
    _req_counts[ip].append(now)

def check_login_attempts(ip: str):
    now = time.time()
    _login_fails[ip] = [t for t in _login_fails[ip] if now - t < 900]
    if len(_login_fails[ip]) >= 5:
        raise HTTPException(429, "Demasiados intentos. Espera 15 minutos.")

def register_login_failure(ip: str):
    _login_fails[ip].append(time.time())

# ─── APP ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="SplunkGuard AI", version="1.0.0", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
security_scheme = HTTPBearer()

SKIP_RATE_LIMIT = {"/health", "/"}

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    if request.url.path not in SKIP_RATE_LIMIT:
        try:
            rate_limit(ip)
        except HTTPException as e:
            return JSONResponse(status_code=429, content={"detail": e.detail})
    logger.info(f"{request.method} {request.url.path} | IP: {ip}")
    response = await call_next(request)
    response.headers["X-Content-Type-Options"]       = "nosniff"
    response.headers["X-Frame-Options"]              = "DENY"
    response.headers["X-XSS-Protection"]             = "1; mode=block"
    response.headers["Strict-Transport-Security"]    = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"]      = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https:; img-src * data:"
    return response

# ─── MODELOS ───────────────────────────────────────────────────────────────────
class UserRegister(BaseModel):
    email: str
    password: str
    org_name: str
    lang: str = "es"

    @validator("email")
    def email_valid(cls, v):
        v = v.lower().strip()
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Correo inválido")
        return v

    @validator("password")
    def password_strong(cls, v):
        if len(v) < 8:            raise ValueError("Mínimo 8 caracteres")
        if not re.search(r"[A-Z]", v): raise ValueError("Una mayúscula requerida")
        if not re.search(r"[0-9]", v): raise ValueError("Un número requerido")
        return v

    @validator("lang")
    def lang_valid(cls, v):
        return v if v in TRANSLATIONS else "en"

class UserLogin(BaseModel):
    email: str
    password: str

class MetricIngest(BaseModel):
    host: str
    cpu: float
    memory: float
    disk: Optional[float] = None
    requests_per_sec: Optional[float] = None
    error_rate: Optional[float] = None
    lang: Optional[str] = "en"

class SecurityEvent(BaseModel):
    host: str
    type: str           # brute_force | unknown_ip | port_scan | data_exfil | malware
    ip: Optional[str]   = None
    count: Optional[int] = 1
    details: Optional[str] = None
    lang: Optional[str] = "en"

class IncidentCreate(BaseModel):
    title: str
    severity: str = "MEDIUM"   # LOW | MEDIUM | HIGH | CRITICAL
    description: Optional[str] = None
    host: Optional[str] = None

class ChatMessage(BaseModel):
    message: str
    lang: Optional[str] = "en"

class IncidentResolve(BaseModel):
    resolution: str

# ─── HELPERS ───────────────────────────────────────────────────────────────────
def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security_scheme)):
    try:
        user = supabase.auth.get_user(creds.credentials)
        if not user or not user.user:
            raise HTTPException(401, "Token inválido")
        return {"user": user.user, "token": creds.credentials}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(401, f"Sesión expirada: {e}")

def get_org(user_id: str):
    try:
        res = supabase.table("org_members").select("*, organizations(*)").eq("user_id", user_id).execute()
        if not res.data:
            raise HTTPException(404, "No pertenece a ninguna organización")
        return {
            "org_id": res.data[0]["org_id"],
            "role":   res.data[0]["role"],
            "lang":   res.data[0]["organizations"].get("lang", "en"),
            "org":    res.data[0]["organizations"]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(503, f"DB no disponible: {e}")

def require_admin(org_info):
    if org_info["role"] != "admin":
        raise HTTPException(403, "Requiere permisos de administrador")

# ─── AUTH ──────────────────────────────────────────────────────────────────────
@app.post("/register")
def register(data: UserRegister, request: Request):
    ip = request.client.host if request.client else "unknown"
    rate_limit(ip, max_req=5, window=300)
    try:
        user = supabase.auth.sign_up({"email": data.email, "password": data.password})
        if not user.user:
            raise HTTPException(400, "Correo ya registrado")
        org = supabase.table("organizations").insert({"nombre": data.org_name, "lang": data.lang}).execute()
        org_id = org.data[0]["id"]
        supabase.table("org_members").insert({"user_id": user.user.id, "org_id": org_id, "role": "admin"}).execute()
        splunk.send_event({"type": "user_registered", "org": data.org_name, "lang": data.lang})
        return {"message": t(data.lang, "welcome")}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Error al registrar: {e}")

@app.post("/login")
def login(data: UserLogin, request: Request):
    ip = request.client.host if request.client else "unknown"
    check_login_attempts(ip)
    try:
        result = supabase.auth.sign_in_with_password({"email": data.email.lower().strip(), "password": data.password})
        if not result.session:
            register_login_failure(ip)
            raise HTTPException(401, "Credenciales incorrectas")
        splunk.send_event({"type": "login_success", "email": data.email, "ip": ip},
                          sourcetype="splunkguard:auth")
        return {"access_token": result.session.access_token, "token_type": "bearer"}
    except HTTPException:
        register_login_failure(ip)
        raise
    except Exception as e:
        register_login_failure(ip)
        splunk.send_event({"type": "login_failed", "email": data.email, "ip": ip},
                          sourcetype="splunkguard:security")
        raise HTTPException(401, "Credenciales incorrectas")

# ─── MÓDULO 1: OBSERVABILIDAD ──────────────────────────────────────────────────
@app.post("/observability/metrics")
def ingest_metric(data: MetricIngest, auth=Depends(get_current_user)):
    org_info = get_org(auth["user"].id)
    lang     = data.lang or org_info["lang"]
    record   = {
        "org_id": org_info["org_id"], "host": data.host,
        "cpu": data.cpu, "memory": data.memory,
        "disk": data.disk, "requests_per_sec": data.requests_per_sec,
        "error_rate": data.error_rate, "created_at": datetime.now().isoformat()
    }
    supabase.table("metrics").insert(record).execute()
    splunk.send_event(record, sourcetype="splunkguard:metrics")
    alerts = []
    if data.cpu > 85:
        msg = t(lang, "alert_cpu", host=data.host, value=data.cpu)
        alerts.append(msg)
        supabase.table("incidents").insert({
            "org_id": org_info["org_id"], "title": msg,
            "severity": "HIGH" if data.cpu > 95 else "MEDIUM",
            "host": data.host, "status": "open",
            "created_at": datetime.now().isoformat()
        }).execute()
    if data.memory > 90:
        msg = t(lang, "alert_memory", host=data.host, value=data.memory)
        alerts.append(msg)
    return {"status": "ingested", "alerts": alerts, "host": data.host}

@app.get("/observability/metrics")
def get_metrics(auth=Depends(get_current_user)):
    org_info = get_org(auth["user"].id)
    metrics  = supabase.table("metrics").select("*").eq("org_id", org_info["org_id"])\
        .order("created_at", desc=True).limit(100).execute().data or []
    hosts    = list({m["host"] for m in metrics})
    predictions = []
    for host in hosts:
        h = [m for m in metrics if m["host"] == host]
        pred = predict_failure(host, h)
        if pred["prediction"]:
            predictions.append(pred)
    return {"metrics": metrics, "predictions": predictions, "total_hosts": len(hosts)}

@app.get("/observability/anomalies")
def get_anomalies(auth=Depends(get_current_user)):
    org_info = get_org(auth["user"].id)
    lang     = org_info["lang"]
    metrics  = supabase.table("metrics").select("*").eq("org_id", org_info["org_id"])\
        .gte("created_at", (datetime.now() - timedelta(hours=24)).isoformat())\
        .order("created_at", desc=True).execute().data or []
    anomalies = []
    for m in metrics:
        if m.get("cpu", 0) > 85:
            anomalies.append({"type": "high_cpu", "host": m["host"],
                               "value": m["cpu"], "timestamp": m["created_at"],
                               "message": t(lang, "alert_cpu", host=m["host"], value=m["cpu"])})
        if m.get("memory", 0) > 90:
            anomalies.append({"type": "high_memory", "host": m["host"],
                               "value": m["memory"], "timestamp": m["created_at"],
                               "message": t(lang, "alert_memory", host=m["host"], value=m["memory"])})
        if m.get("error_rate", 0) and m["error_rate"] > 5:
            anomalies.append({"type": "high_error_rate", "host": m["host"],
                               "value": m["error_rate"], "timestamp": m["created_at"],
                               "message": t(lang, "alert_anomaly", desc=f"Error rate {m['error_rate']}% en {m['host']}")})
    return {"anomalies": anomalies, "total": len(anomalies)}

# ─── MÓDULO 2: SEGURIDAD ───────────────────────────────────────────────────────
@app.post("/security/events")
ef ingest_security_event(data: SecurityEvent, auth=Depends(get_current_user)):
    org_info = get_org(auth["user"].id)
    lang     = data.lang or org_info["lang"]
    record   = {
        "org_id": org_info["org_id"], "host": data.host,
        "type": data.type, "ip": data.ip, "count": data.count,
        "details": data.details, "created_at": datetime.now().isoformat()
    }
    supabase.table("security_events").insert(record).execute()
    splunk.send_event(record, sourcetype="splunkguard:security")
    alert_msg = ""
    if data.type == "brute_force":
        alert_msg = t(lang, "alert_security", ip=data.ip or "unknown", count=data.count)
        auto_remediate("brute_force", data.host, lang)
    elif data.type == "unknown_ip":
        alert_msg = t(lang, "alert_security", ip=data.ip or "unknown", count=data.count)
    if alert_msg:
        supabase.table("incidents").insert({
            "org_id": org_info["org_id"], "title": alert_msg,
            "severity": "CRITICAL" if data.type in ["brute_force", "malware"] else "HIGH",
            "host": data.host, "status": "open",
            "created_at": datetime.now().isoformat()
        }).execute()
        send_slack(f"🚨 *SplunkGuard Security Alert*\n{alert_msg}")
    return {"status": "recorded", "alert": alert_msg}

@app.get("/security/threats")
def get_threats(auth=Depends(get_current_user)):
    org_info = get_org(auth["user"].id)
    since    = (datetime.now() - timedelta(hours=24)).isoformat()
    events   = supabase.table("security_events").select("*").eq("org_id", org_info["org_id"])\
        .gte("created_at", since).order("created_at", desc=True).execute().data or []
    by_type  = defaultdict(int)
    by_ip    = defaultdict(int)
    for e in events:
        by_type[e["type"]] += 1
        if e.get("ip"):
            by_ip[e["ip"]] += 1
    top_ips = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "events": events[:50], "total": len(events),
        "by_type": dict(by_type),
        "top_suspicious_ips": [{"ip": ip, "count": c} for ip, c in top_ips]
    }

@app.get("/security/risk-score")
def get_risk_score(auth=Depends(get_current_user)):
    org_info = get_org(auth["user"].id)
    org_id   = org_info["org_id"]
    metrics  = supabase.table("metrics").select("*").eq("org_id", org_id)\
        .order("created_at", desc=True).limit(20).execute().data or []
    sec_evts = supabase.table("security_events").select("*").eq("org_id", org_id)\
        .gte("created_at", (datetime.now() - timedelta(hours=1)).isoformat()).execute().data or []
    correlation = correlate_events(metrics, sec_evts)
    supabase.table("risk_scores").upsert({
        "org_id": org_id, "score": correlation["risk_score"],
        "level": correlation["level"], "updated_at": datetime.now().isoformat()
    }).execute()
    return correlation

# ─── MÓDULO 3: PLATAFORMA — AGENTE IA ─────────────────────────────────────────
@app.post("/platform/chat")
async def chat_with_agent(data: ChatMessage, auth=Depends(get_current_user)):
    org_info = get_org(auth["user"].id)
    org_id   = org_info["org_id"]
    lang     = data.lang or org_info["lang"]
    metrics  = supabase.table("metrics").select("*").eq("org_id", org_id)\
        .order("created_at", desc=True).limit(20).execute().data or []
    sec_evts = supabase.table("security_events").select("*").eq("org_id", org_id)\
        .order("created_at", desc=True).limit(20).execute().data or []
    incidents = supabase.table("incidents").select("*").eq("org_id", org_id)\
        .eq("status", "open").execute().data or []
    correlation = correlate_events(metrics, sec_evts)
    context = {
        "organization":       org_info["org"]["nombre"],
        "language":           lang,
        "recent_metrics":     metrics[:5],
        "recent_threats":     sec_evts[:5],
        "open_incidents":     incidents[:5],
        "current_risk_score": correlation["risk_score"],
        "risk_level":         correlation["level"],
        "correlated_alerts":  correlation["correlated_alerts"],
        "timestamp":          datetime.now().isoformat()
    }
    response = await ai_analyze(data.message, context)
    supabase.table("chat_history").insert({
        "org_id": org_id, "user_message": data.message,
        "ai_response": response, "lang": lang,
        "created_at": datetime.now().isoformat()
    }).execute()
    splunk.send_event({"type": "ai_chat", "lang": lang, "org_id": org_id},
                      sourcetype="splunkguard:platform")
    return {"response": response, "context_used": {"risk_score": correlation["risk_score"],
            "open_incidents": len(incidents), "recent_threats": len(sec_evts)}}

@app.get("/platform/chat/history")
def chat_history(auth=Depends(get_current_user)):
    org_info = get_org(auth["user"].id)
    history  = supabase.table("chat_history").select("*").eq("org_id", org_info["org_id"])\
        .order("created_at", desc=True).limit(50).execute().data or []
    return {"history": history}

# ─── INCIDENTES ────────────────────────────────────────────────────────────────
@app.get("/incidents")
def get_incidents(auth=Depends(get_current_user)):
    org_info  = get_org(auth["user"].id)
    incidents = supabase.table("incidents").select("*").eq("org_id", org_info["org_id"])\
        .order("created_at", desc=True).limit(100).execute().data or []
    open_i    = [i for i in incidents if i["status"] == "open"]
    resolved  = [i for i in incidents if i["status"] == "resolved"]
    return {"incidents": incidents, "open": len(open_i), "resolved": len(resolved), "total": len(incidents)}

@app.post("/incidents")
def create_incident(data: IncidentCreate, auth=Depends(get_current_user)):
    org_info = get_org(auth["user"].id)
    lang     = org_info["lang"]
    res = supabase.table("incidents").insert({
        "org_id": org_info["org_id"], "title": data.title,
        "severity": data.severity, "description": data.description,
        "host": data.host, "status": "open",
        "created_at": datetime.now().isoformat()
    }).execute()
    inc_id = res.data[0]["id"]
    msg    = t(lang, "incident_created", id=inc_id, title=data.title)
    splunk.send_event({"type": "incident_created", "id": inc_id,
                       "severity": data.severity, "title": data.title},
                      sourcetype="splunkguard:incident")
    send_slack(f"🚨 {msg}")
    return {"id": inc_id, "message": msg}

@app.put("/incidents/{inc_id}/resolve")
def resolve_incident(inc_id: str, data: IncidentResolve, auth=Depends(get_current_user)):
    org_info = get_org(auth["user"].id)
    check = supabase.table("incidents").select("id").eq("id", inc_id)\
        .eq("org_id", org_info["org_id"]).execute()
    if not check.data:
        raise HTTPException(404, "Incidente no encontrado")
    supabase.table("incidents").update({
        "status": "resolved", "resolution": data.resolution,
        "resolved_at": datetime.now().isoformat()
    }).eq("id", inc_id).execute()
    splunk.send_event({"type": "incident_resolved", "id": inc_id},
                      sourcetype="splunkguard:incident")
    return {"message": f"Incidente #{inc_id} resuelto"}

# ─── DASHBOARD GLOBAL ──────────────────────────────────────────────────────────
@app.get("/dashboard")
def dashboard(auth=Depends(get_current_user)):
    org_info  = get_org(auth["user"].id)
    org_id    = org_info["org_id"]
    metrics   = supabase.table("metrics").select("*").eq("org_id", org_id)\
        .order("created_at", desc=True).limit(50).execute().data or []
    sec_evts  = supabase.table("security_events").select("*").eq("org_id", org_id)\
        .gte("created_at", (datetime.now() - timedelta(hours=24)).isoformat()).execute().data or []
    incidents = supabase.table("incidents").select("*").eq("org_id", org_id)\
        .order("created_at", desc=True).limit(20).execute().data or []
    preds     = supabase.table("predictions").select("*").eq("org_id", org_id).execute().data or []
    correlation = correlate_events(metrics, sec_evts)
    open_incidents = [i for i in incidents if i["status"] == "open"]
    return {
        "org":             org_info["org"]["nombre"],
        "lang":            org_info["lang"],
        "risk_score":      correlation["risk_score"],
        "risk_level":      correlation["level"],
        "correlated_alerts": correlation["correlated_alerts"],
        "observability": {
            "total_hosts":    len({m["host"] for m in metrics}),
            "total_metrics":  len(metrics),
            "avg_cpu":        round(sum(m.get("cpu", 0) for m in metrics) / max(len(metrics), 1), 1),
            "avg_memory":     round(sum(m.get("memory", 0) for m in metrics) / max(len(metrics), 1), 1),
            "predictions":    preds,
        },
        "security": {
            "total_threats_24h": len(sec_evts),
            "brute_force":       len([e for e in sec_evts if e["type"] == "brute_force"]),
            "unknown_ips":       len([e for e in sec_evts if e["type"] == "unknown_ip"]),
        },
        "incidents": {
            "open":     len(open_incidents),
            "resolved": len([i for i in incidents if i["status"] == "resolved"]),
            "critical": len([i for i in open_incidents if i["severity"] == "CRITICAL"]),
            "latest":   incidents[:5],
        }
    }

@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0", "service": "SplunkGuard AI",
            "languages": list(TRANSLATIONS.keys()), "timestamp": datetime.now().isoformat()}

# ─── FRONTEND ───────────────────────────────
@app.get("/", response_class=HTMLResponse)
def frontend():
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>SplunkGuard AI</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet"/>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0e1a;--surface:#111827;--surface2:#1a2235;--border:#1e2d45;
  --accent:#38bdf8;--accent2:#818cf8;--danger:#f43f5e;--warn:#fb923c;
  --success:#34d399;--text:#e2e8f0;--muted:#64748b;
  --font:'Space Grotesk',sans-serif;--mono:'JetBrains Mono',monospace;
}
body{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh}
nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 2rem;
    border-bottom:1px solid var(--border);background:rgba(10,14,26,.95);
    backdrop-filter:blur(12px);position:sticky;top:0;z-index:100}
.logo{display:flex;align-items:center;gap:.6rem;font-size:1.1rem;font-weight:700}
.logo span{color:var(--accent)}
.nav-lang select{background:var(--surface2);border:1px solid var(--border);color:var(--text);
  padding:.4rem .8rem;border-radius:6px;font-family:var(--font);font-size:.82rem;cursor:pointer}
.hero{text-align:center;padding:5rem 2rem 3rem;position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse 80% 50% at 50% -10%,rgba(56,189,248,.12),transparent);pointer-events:none}
.badge{display:inline-block;background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.3);
  color:var(--accent);padding:.35rem 1rem;border-radius:99px;font-size:.78rem;font-weight:600;
  letter-spacing:.05em;margin-bottom:1.5rem}
h1{font-size:clamp(2rem,5vw,3.5rem);font-weight:700;line-height:1.1;margin-bottom:1rem}
h1 em{font-style:normal;
  background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero p{color:var(--muted);font-size:1.1rem;max-width:580px;margin:0 auto 2.5rem}
.hero-btns{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap}
.btn-p{background:var(--accent);color:#0a0e1a;padding:.8rem 2rem;border-radius:8px;
  font-weight:700;text-decoration:none;font-family:var(--font);transition:.2s;border:none;cursor:pointer;font-size:.95rem}
.btn-p:hover{filter:brightness(1.15)}
.btn-g{background:transparent;color:var(--text);padding:.8rem 2rem;border-radius:8px;
  font-weight:600;text-decoration:none;border:1px solid var(--border);font-family:var(--font);
  transition:.2s;cursor:pointer;font-size:.95rem}
.btn-g:hover{border-color:var(--accent);color:var(--accent)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;max-width:700px;margin:3rem auto 0;padding:2rem;
  background:var(--surface);border:1px solid var(--border);border-radius:12px}
.stat-n{font-size:1.8rem;font-weight:700;font-family:var(--mono);color:var(--accent)}
.stat-l{font-size:.78rem;color:var(--muted);margin-top:.2rem}
.modules{display:grid;grid-template-columns:repeat(3,1fr);gap:1.5rem;padding:2rem 2rem 0;max-width:1100px;margin:0 auto}
.module{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem;
  transition:.2s;cursor:default}
.module:hover{border-color:var(--accent);transform:translateY(-2px)}
.mod-icon{font-size:1.8rem;margin-bottom:.8rem}
.mod-title{font-size:1rem;font-weight:700;margin-bottom:.4rem}
.mod-desc{font-size:.83rem;color:var(--muted);line-height:1.5}
.mod-tags{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.8rem}
.tag{background:rgba(56,189,248,.08);border:1px solid rgba(56,189,248,.2);color:var(--accent);
  font-size:.7rem;padding:.2rem .6rem;border-radius:99px;font-family:var(--mono)}
.dashboard-section{max-width:1100px;margin:2rem auto;padding:0 2rem}
.sec-title{font-size:1.4rem;font-weight:700;margin-bottom:1.2rem;display:flex;align-items:center;gap:.5rem}
.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.2rem;text-align:center}
.kpi-val{font-size:2rem;font-weight:700;font-family:var(--mono)}
.kpi-lbl{font-size:.75rem;color:var(--muted);margin-top:.3rem}
.kpi.danger .kpi-val{color:var(--danger)}
.kpi.warn   .kpi-val{color:var(--warn)}
.kpi.ok     .kpi-val{color:var(--success)}
.kpi.info   .kpi-val{color:var(--accent)}
.risk-bar{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.5rem;margin-bottom:1rem}
.risk-label{display:flex;justify-content:space-between;margin-bottom:.8rem;font-size:.9rem}
.risk-track{background:var(--surface2);border-radius:99px;height:12px;overflow:hidden}
.risk-fill{height:100%;border-radius:99px;transition:width .5s ease;
  background:linear-gradient(90deg,var(--success),var(--warn),var(--danger))}
.chat-box{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.chat-msgs{height:320px;overflow-y:auto;padding:1.2rem;display:flex;flex-direction:column;gap:.8rem}
.msg-user{align-self:flex-end;background:rgba(56,189,248,.12);border:1px solid rgba(56,189,248,.2);
  color:var(--text);padding:.7rem 1rem;border-radius:10px 10px 2px 10px;max-width:75%;font-size:.87rem}
.msg-ai{align-self:flex-start;background:var(--surface2);border:1px solid var(--border);
  color:var(--text);padding:.7rem 1rem;border-radius:10px 10px 10px 2px;max-width:85%;font-size:.87rem;line-height:1.5}
.msg-ai strong{color:var(--accent)}
.chat-input{display:flex;border-top:1px solid var(--border)}
.chat-input input{flex:1;background:transparent;border:none;color:var(--text);padding:1rem 1.2rem;
  font-family:var(--font);font-size:.9rem;outline:none}
.chat-input input::placeholder{color:var(--muted)}
.chat-send{background:var(--accent);color:#0a0e1a;border:none;padding:.8rem 1.4rem;
  font-family:var(--font);font-weight:700;cursor:pointer;transition:.2s;font-size:.9rem}
.chat-send:hover{filter:brightness(1.1)}
.chat-send:disabled{opacity:.5;cursor:not-allowed}
.incidents-list{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.inc-header{padding:1rem 1.2rem;border-bottom:1px solid var(--border);font-weight:600;font-size:.9rem}
.inc-item{display:flex;align-items:center;gap:1rem;padding:.9rem 1.2rem;
  border-bottom:1px solid var(--border);font-size:.83rem}
.inc-item:last-child{border-bottom:none}
.sev{padding:.2rem .6rem;border-radius:4px;font-size:.7rem;font-weight:700;font-family:var(--mono)}
.sev.CRITICAL{background:rgba(244,63,94,.15);color:#f43f5e}
.sev.HIGH    {background:rgba(251,146,60,.15);color:#fb923c}
.sev.MEDIUM  {background:rgba(234,179,8,.15); color:#eab308}
.sev.LOW     {background:rgba(52,211,153,.15);color:#34d399}
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);
  backdrop-filter:blur(4px);z-index:200;align-items:center;justify-content:center}
.modal-bg.on{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:14px;
  padding:2rem;width:90%;max-width:440px;position:relative}
.close-btn{position:absolute;top:1rem;right:1rem;background:none;border:none;
  color:var(--muted);font-size:1.2rem;cursor:pointer}
.close-btn:hover{color:var(--text)}
.tabs{display:flex;gap:.5rem;margin-bottom:1.5rem}
.tab{flex:1;padding:.6rem;background:var(--surface2);border:1px solid var(--border);
  color:var(--muted);border-radius:7px;font-family:var(--font);font-size:.85rem;cursor:pointer;transition:.2s}
.tab.on{background:var(--accent);color:#0a0e1a;border-color:var(--accent);font-weight:700}
.fg{margin-bottom:.9rem}
.fg label{display:block;font-size:.78rem;color:var(--muted);margin-bottom:.35rem;font-weight:500}
.fg input,.fg select{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);
  padding:.7rem .9rem;border-radius:7px;font-size:.92rem;outline:none;font-family:var(--font);transition:.2s}
.fg input:focus,.fg select:focus{border-color:var(--accent)}
.fg select option{background:var(--surface)}
.f-btn{width:100%;margin-top:.8rem;padding:.85rem;background:var(--accent);color:#0a0e1a;border:none;
  border-radius:7px;font-family:var(--font);font-weight:700;font-size:.95rem;cursor:pointer;transition:.2s}
.f-btn:hover{filter:brightness(1.1)}
.msg{margin-top:.8rem;padding:.65rem .9rem;border-radius:7px;font-size:.83rem;display:none}
.msg.err{background:rgba(244,63,94,.1);border:1px solid rgba(244,63,94,.25);color:#f43f5e;display:block}
.msg.ok {background:rgba(52,211,153,.1); border:1px solid rgba(52,211,153,.25);color:#34d399;display:block}
.lang-chips{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.4rem}
.lang-chip{padding:.3rem .7rem;border-radius:99px;background:rgba(129,140,248,.1);
  border:1px solid rgba(129,140,248,.3);color:var(--accent2);font-size:.75rem;
  font-family:var(--mono);cursor:pointer;transition:.2s}
.lang-chip:hover{background:rgba(129,140,248,.2)}
footer{border-top:1px solid var(--border);padding:1.8rem;text-align:center;
  color:var(--muted);font-size:.8rem;margin-top:4rem}
@media(max-width:768px){
  .modules{grid-template-columns:1fr}
  .grid4{grid-template-columns:repeat(2,1fr)}
  .stats{grid-template-columns:repeat(2,1fr)}
}
</style>
</head>
<body>
<nav>
  <div class="logo">
    <svg width="28" height="28" viewBox="0 0 32 32" fill="none">
      <rect width="32" height="32" rx="7" fill="#38bdf8"/>
      <path d="M6 20L11 13L16 17L21 11L26 14" stroke="#0a0e1a" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="26" cy="9" r="3" fill="#818cf8"/>
      <path d="M6 25H26" stroke="#0a0e1a" stroke-width="1.5" stroke-linecap="round" opacity=".4"/>
    </svg>
    Splunk<span>Guard</span> AI
  </div>
  <div style="display:flex;align-items:center;gap:1rem">
    <div class="nav-lang">
      <select id="globalLang" onchange="setLang(this.value)">
        <option value="es">🇪🇸 ES</option>
        <option value="en">🇺🇸 EN</option>
        <option value="pt">🇧🇷 PT</option>
        <option value="fr">🇫🇷 FR</option>
        <option value="de">🇩🇪 DE</option>
        <option value="it">🇮🇹 IT</option>
        <option value="zh">🇨🇳 ZH</option>
        <option value="ja">🇯🇵 JA</option>
        <option value="ar">🇸🇦 AR</option>
        <option value="ru">🇷🇺 RU</option>
      </select>
    </div>
    <button class="btn-p" onclick="openM('login')" style="padding:.5rem 1.2rem;font-size:.85rem" id="loginBtn">Iniciar sesión</button>
    <button class="btn-g" onclick="logout()" id="logoutBtn" style="display:none;padding:.5rem 1.2rem;font-size:.85rem">Salir</button>
  </div>
</nav>

<section class="hero">
  <div class="badge">🤖 Splunk Agentic Ops Hackathon 2026</div>
  <h1>El agente de IA que <em>protege y observa</em> tus operaciones</h1>
  <p>Observabilidad, seguridad y plataforma unificadas. Detección automática, remediación inteligente y análisis en 10 idiomas.</p>
  <div class="hero-btns">
    <button class="btn-p" onclick="openM('register')">Comenzar gratis</button>
    <a href="#modules" class="btn-g">Ver módulos</a>
  </div>
  <div class="stats">
    <div><div class="stat-n">3</div><div class="stat-l">Módulos IA</div></div>
    <div><div class="stat-n">10</div><div class="stat-l">Idiomas</div></div>
    <div><div class="stat-n">24/7</div><div class="stat-l">Monitoreo</div></div>
    <div><div class="stat-n">Auto</div><div class="stat-l">Remediación</div></div>
  </div>
</section>

<div id="modules">
<div class="modules">
  <div class="module">
    <div class="mod-icon">🔍</div>
    <div class="mod-title">Observabilidad</div>
    <div class="mod-desc">Ingesta métricas de CPU, memoria y errores. Detecta anomalías en tiempo real y predice fallos antes de que ocurran.</div>
    <div class="mod-tags"><span class="tag">anomaly-detection</span><span class="tag">prediction</span><span class="tag">splunk-hec</span></div>
  </div>
  <div class="module">
    <div class="mod-icon">🔒</div>
    <div class="mod-title">Seguridad</div>
    <div class="mod-desc">Analiza eventos de seguridad, detecta fuerza bruta e IPs desconocidas. Auto-bloqueo y correlación cruzada con observabilidad.</div>
    <div class="mod-tags"><span class="tag">threat-detection</span><span class="tag">auto-block</span><span class="tag">correlation</span></div>
  </div>
  <div class="module">
    <div class="mod-icon">⚙️</div>
    <div class="mod-title">Plataforma IA</div>
    <div class="mod-desc">Pregúntale al agente en lenguaje natural. Análisis contextual, historial de conversaciones y respuestas en 10 idiomas.</div>
    <div class="mod-tags"><span class="tag">ai-agent</span><span class="tag">nlp</span><span class="tag">10-langs</span></div>
  </div>
</div>
</div>

<div id="dashboardSection" style="display:none">
<div class="dashboard-section">
  <div class="sec-title">📊 Dashboard en tiempo real</div>
  <div class="risk-bar">
    <div class="risk-label">
      <span>Score de riesgo global</span>
      <span id="riskVal" style="font-family:var(--mono);font-weight:700">--/100</span>
    </div>
    <div class="risk-track"><div class="risk-fill" id="riskFill" style="width:0%"></div></div>
    <div id="riskLevel" style="margin-top:.5rem;font-size:.8rem;color:var(--muted)"></div>
  </div>
  <div class="grid4" id="kpiGrid">
    <div class="kpi info"><div class="kpi-val" id="kpiHosts">--</div><div class="kpi-lbl">Hosts monitoreados</div></div>
    <div class="kpi warn"><div class="kpi-val" id="kpiThreats">--</div><div class="kpi-lbl">Amenazas 24h</div></div>
    <div class="kpi danger"><div class="kpi-val" id="kpiIncidents">--</div><div class="kpi-lbl">Incidentes abiertos</div></div>
    <div class="kpi ok"><div class="kpi-val" id="kpiResolved">--</div><div class="kpi-lbl">Resueltos</div></div>
  </div>
</div>

<div class="dashboard-section" style="margin-top:1.5rem;display:grid;grid-template-columns:1fr 1fr;gap:1.5rem">
  <div>
    <div class="sec-title">🤖 Agente IA — Pregunta lo que quieras</div>
    <div class="chat-box">
      <div class="chat-msgs" id="chatMsgs">
        <div class="msg-ai"><strong>SplunkGuard AI:</strong> Hola, soy tu agente de operaciones. Puedes preguntarme sobre amenazas, métricas, incidentes o cualquier cosa sobre tu infraestructura.</div>
      </div>
      <div class="chat-input">
        <input id="chatInput" placeholder="¿Qué pasó en las últimas horas?" onkeydown="if(event.key==='Enter')sendChat()"/>
        <button class="chat-send" id="chatSendBtn" onclick="sendChat()">Enviar</button>
      </div>
    </div>
  </div>
  <div>
    <div class="sec-title">🚨 Incidentes recientes</div>
    <div class="incidents-list" id="incidentsList">
      <div class="inc-header">Últimos incidentes</div>
      <div style="padding:2rem;text-align:center;color:var(--muted);font-size:.85rem">Cargando...</div>
    </div>
  </div>
</div>
</div>

<div class="modal-bg" id="mbg" onclick="closeOut(event)">
<div class="modal">
  <button class="close-btn" onclick="closeM()">✕</button>
  <h2 style="margin-bottom:.3rem">Bienvenido</h2>
  <p style="color:var(--muted);font-size:.85rem;margin-bottom:1.2rem">Accede o crea tu cuenta</p>
  <div class="tabs">
    <button class="tab on" id="tl" onclick="swTab('login')">Iniciar sesión</button>
    <button class="tab" id="tr2" onclick="swTab('register')">Registrarse</button>
  </div>
  <div id="lf">
    <div class="fg"><label>Correo</label><input type="email" id="le" placeholder="tu@empresa.com"/></div>
    <div class="fg"><label>Contraseña</label><input type="password" id="lp" placeholder="••••••••"/></div>
    <div class="msg" id="lm"></div>
    <button class="f-btn" onclick="doLogin()">Iniciar sesión</button>
  </div>
  <div id="rf" style="display:none">
    <div class="fg"><label>Empresa</label><input type="text" id="ro" placeholder="Mi Empresa S.A."/></div>
    <div class="fg"><label>Correo</label><input type="email" id="re" placeholder="tu@empresa.com"/></div>
    <div class="fg"><label>Contraseña</label><input type="password" id="rp" placeholder="Mín 8 chars, 1 mayúscula, 1 número"/></div>
    <div class="fg">
      <label>Idioma preferido</label>
      <select id="rlang">
        <option value="es">🇪🇸 Español</option>
        <option value="en">🇺🇸 English</option>
        <option value="pt">🇧🇷 Português</option>
        <option value="fr">🇫🇷 Français</option>
        <option value="de">🇩🇪 Deutsch</option>
        <option value="it">🇮🇹 Italiano</option>
        <option value="zh">🇨🇳 中文</option>
        <option value="ja">🇯🇵 日本語</option>
        <option value="ar">🇸🇦 العربية</option>
        <option value="ru">🇷🇺 Русский</option>
      </select>
    </div>
    <div class="msg" id="rm"></div>
    <button class="f-btn" onclick="doReg()">Crear cuenta gratis</button>
  </div>
</div>
</div>

<footer><p>© 2026 SplunkGuard AI — Splunk Agentic Ops Hackathon &nbsp;|&nbsp; Powered by Splunk AI + Anthropic Claude</p></footer>

<script>
const API = '';
let token = localStorage.getItem('sg_token');
let currentLang = localStorage.getItem('sg_lang') || 'es';

function setLang(l){ currentLang = l; localStorage.setItem('sg_lang', l); }
function openM(tab){ document.getElementById('mbg').classList.add('on'); swTab(tab||'login'); }
function closeM(){ document.getElementById('mbg').classList.remove('on'); }
function closeOut(e){ if(e.target===document.getElementById('mbg')) closeM(); }
function swTab(tab){
  const isL = tab==='login';
  document.getElementById('lf').style.display = isL?'':'none';
  document.getElementById('rf').style.display = isL?'none':'';
  document.getElementById('tl').classList.toggle('on', isL);
  document.getElementById('tr2').classList.toggle('on', !isL);
}
function showMsg(id, txt, type){ const e=document.getElementById(id); e.textContent=txt; e.className='msg '+type; }
function logout(){ localStorage.removeItem('sg_token'); token=null; location.reload(); }

async function doLogin(){
  const email=document.getElementById('le').value, password=document.getElementById('lp').value;
  try{
    const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});
    const d=await r.json();
    if(!r.ok){ showMsg('lm',d.detail||'Error','err'); return; }
    token=d.access_token; localStorage.setItem('sg_token',token);
    showMsg('lm','✓ Bienvenido','ok');
    setTimeout(()=>{ closeM(); showDashboard(); }, 900);
  }catch(e){ showMsg('lm','Error de conexión','err'); }
}

async function doReg(){
  const org_name=document.getElementById('ro').value, email=document.getElementById('re').value,
        password=document.getElementById('rp').value, lang=document.getElementById('rlang').value;
  try{
    const r=await fetch('/register',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({email,password,org_name,lang})});
    const d=await r.json();
    if(!r.ok){ const m=d.detail?.map?d.detail.map(e=>e.msg).join(', '):d.detail; showMsg('rm',m||'Error','err'); return; }
    showMsg('rm','✓ Cuenta creada — inicia sesión','ok'); setTimeout(()=>swTab('login'), 1800);
  }catch(e){ showMsg('rm','Error de conexión','err'); }
}

async function showDashboard(){
  if(!token) return;
  document.getElementById('dashboardSection').style.display='block';
  document.getElementById('loginBtn').style.display='none';
  document.getElementById('logoutBtn').style.display='block';
  await loadDashboard();
  await loadIncidents();
  setInterval(loadDashboard, 30000);
}
async function loadDashboard(){
  try{
    const r=await fetch('/dashboard',{headers:{'Authorization':'Bearer '+token}});
    if(!r.ok) return;
    const d=await r.json();
    document.getElementById('riskVal').textContent = d.risk_score+'/100';
    document.getElementById('riskFill').style.width = d.risk_score+'%';
    document.getElementById('riskLevel').textContent = 'Nivel: '+d.risk_level+' | Org: '+d.org;
    document.getElementById('kpiHosts').textContent     = d.observability.total_hosts;
    document.getElementById('kpiThreats').textContent   = d.security.total_threats_24h;
    document.getElementById('kpiIncidents').textContent = d.incidents.open;
    document.getElementById('kpiResolved').textContent  = d.incidents.resolved;
  }catch(e){ console.error(e); }
}

async function loadIncidents(){
  try{
    const r=await fetch('/incidents',{headers:{'Authorization':'Bearer '+token}});
    if(!r.ok) return;
    const d=await r.json();
    const el=document.getElementById('incidentsList');
    if(!d.incidents.length){ el.innerHTML='<div class="inc-header">Últimos incidentes</div><div style="padding:2rem;text-align:center;color:var(--muted);font-size:.85rem">Sin incidentes 🎉</div>'; return; }
    el.innerHTML='<div class="inc-header">Últimos incidentes ('+d.open+' abiertos)</div>'+
      d.incidents.slice(0,6).map(i=>`
        <div class="inc-item">
          <span class="sev ${i.severity}">${i.severity}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${i.title}</span>
          <span style="color:var(--muted);font-size:.75rem;font-family:var(--mono)">${i.status}</span>
        </div>`).join('');
  }catch(e){ console.error(e); }
}

async function sendChat(){
  const input=document.getElementById('chatInput');
  const msg=input.value.trim();
  if(!msg || !token) return;
  const btn=document.getElementById('chatSendBtn');
  btn.disabled=true; input.value='';
  const msgs=document.getElementById('chatMsgs');
  msgs.innerHTML+=`<div class="msg-user">${msg}</div>`;
  msgs.innerHTML+=`<div class="msg-ai" id="typing"><em style="color:var(--muted)">SplunkGuard AI está analizando...</em></div>`;
  msgs.scrollTop=msgs.scrollHeight;
  try{
    const r=await fetch('/platform/chat',{method:'POST',headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'},
      body:JSON.stringify({message:msg,lang:currentLang})});
    const d=await r.json();
    document.getElementById('typing').outerHTML=
      `<div class="msg-ai"><strong>SplunkGuard AI:</strong> ${d.response.replace(/\n/g,'<br>')}</div>`;
  }catch(e){
    document.getElementById('typing').outerHTML=`<div class="msg-ai" style="color:var(--danger)">Error al conectar con el agente.</div>`;
  }
  btn.disabled=false;
  msgs.scrollTop=msgs.scrollHeight;
}

document.addEventListener('keydown',e=>{ if(e.key==='Escape') closeM(); });
document.addEventListener('DOMContentLoaded',()=>{
  document.getElementById('globalLang').value = currentLang;
  if(token) showDashboard();
});
</script>
</body>
</html>""")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=False)
