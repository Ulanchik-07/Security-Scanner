import sys
import os
import streamlit as st
import vulners

from dotenv import load_dotenv
load_dotenv()
VULNERS_KEY = os.getenv("VULNERS_API_KEY")
GEMINI_KEY = os.getenv("GEMINI_API_KEY")


def build_local_explanation(text: str) -> str:
    """Simple local explanation for vulnerability text without external AI APIs."""
    t = (text or "").lower()
    lines = [
        "Это уязвимость, которая может позволить злоумышленнику использовать слабое место в ПО.",
        "Чем раньше её закрыть, тем ниже риск компрометации системы или утечки данных.",
    ]
    if "cve" in t:
        lines.append("Ссылка на CVE указывает, что проблема уже зарегистрирована в общественной базе уязвимостей.")
    if any(word in t for word in ("remote", "rce", "execute", "code execution")):
        lines.append("Если присутствует удалённое выполнение кода, это особенно опасно, потому что атака может начаться без физического доступа к системе.")
    if any(word in t for word in ("overflow", "buffer", "memory")):
        lines.append("Проблемы с памятью или переполнением буфера часто приводят к авариям и коду злоумышленника.")
    if any(word in t for word in ("auth", "password", "bypass", "privilege")):
        lines.append("Если речь идёт о доступе или привилегиях, уязвимость может дать доступ к данным или функциям, которые не должны быть доступны.")
    return " ".join(lines)

# Инициализация Gemini API
GEMINI_CLIENT = None
MODEL_CANDIDATES = ["models/gemini-2.0-flash", "models/gemini-2.5-flash"]
if GEMINI_KEY:
    try:
        from google import genai

        GEMINI_CLIENT = genai.Client(api_key=GEMINI_KEY)
    except Exception:
        GEMINI_CLIENT = None

# Убираем конфликты импорта
current_dir = os.path.dirname(os.path.abspath(__file__))
repo_dir = os.path.join(current_dir, 'scanner_module')
if repo_dir in sys.path:
    sys.path.remove(repo_dir)

st.set_page_config(page_title="Vulners Security Suite", page_icon="🛡️", layout="wide")

st.title("🛡️ Профессиональный ИБ-сканер")
st.write("Аудит безопасности с поддержкой ИИ-аналитики.")

# Вкладки
tab1, tab2, tab3 = st.tabs(["🔍 Быстрый поиск", "📋 Пакетный аудит", "🤖 AI-Консультант"])

# --- ВКЛАДКА 1: ПОИСК ---
with tab1:
    software = st.text_input("Название ПО и версия:", placeholder="nginx 1.14.0")
    if st.button("Запустить поиск", type="primary"):
        vulners_api = vulners.VulnersApi(api_key=VULNERS_KEY)
        results = vulners_api.search.search_bulletins(software, limit=5)
        for item in results:
            with st.expander(f"{item['id']} — Опасность: {item.get('cvss', {}).get('score', 0)}"):
                st.write(item.get('title'))
                st.session_state['last_vuln'] = item.get('description', '')

# --- ВКЛАДКА 2: АУДИТ ---
with tab2:
    packages = st.text_area("Список ПО:", "openssl 1.1.1\nnginx 1.14.0", height=100)
    if st.button("Запустить аудит"):
        vulners_api = vulners.VulnersApi(api_key=VULNERS_KEY)
        for pkg in packages.split('\n'):
            res = vulners_api.search.search_bulletins(pkg, limit=2)
            if res:
                st.warning(f"Уязвимости в {pkg}:")
                for r in res:
                    st.write(f"- {r['id']}")

# --- ВКЛАДКА 3: AI-КОНСУЛЬТАНТ ---
with tab3:
    st.subheader("🤖 AI-объяснение уязвимостей")
    query = st.text_area("Вставь описание CVE или результат сканирования сюда:", height=150)
    if st.button("Объяснить просто"):
        if not query.strip():
            st.warning("Введите текст уязвимости или описание CVE.")
        else:
            with st.spinner("Формирую короткое объяснение..."):
                try:
                    if GEMINI_CLIENT and GEMINI_KEY:
                        last_error = None
                        for model_name in MODEL_CANDIDATES:
                            try:
                                response = GEMINI_CLIENT.models.generate_content(
                                    model=model_name,
                                    contents=f"Объясни эту уязвимость максимально просто: {query}",
                                )
                                st.info(getattr(response, "text", str(response)))
                                break
                            except Exception as exc:
                                last_error = exc
                        else:
                            raise last_error or RuntimeError("Не удалось получить ответ Gemini")
                    else:
                        st.info(build_local_explanation(query))
                except Exception as exc:
                    st.warning("AI API не ответил, поэтому показываю локальное объяснение.")
                    st.info(build_local_explanation(query))