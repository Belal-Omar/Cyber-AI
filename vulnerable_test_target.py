"""
================================================================================
VULNERABLE TEST TARGET APPLICATION (FOR SECURITY SCANNER BENCHMARKING)
================================================================================
تطبيق اختباري مصمم عمداً ليحتوي على أشهر الثغرات الأمنية (OWASP Top 10 + SAST/DAST)
الغرض: اختبار وفحص كفاءة أدوات الفحص الأمني (DAST / SAST) مثل CyberAI أو ZAP أو Burp.

طريقة التشغيل:
    python vulnerable_test_target.py
أو:
    uvicorn vulnerable_test_target:app --host 127.0.0.1 --port 5050 --reload

ثم قم بإضافة الرابط في أداة الفحص:
    http://127.0.0.1:5050
================================================================================
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib
import importlib
try:
    jinja2 = importlib.import_module("jinja2")
except Exception:
    jinja2 = None
import httpx
from fastapi import FastAPI, Request, Response, UploadFile, File, Form, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# ==============================================================================
# 1. HARDCODED SECRETS (SAST & Static Code Vulnerability)
# ==============================================================================
# ثغرة تسريب مفاتيح سرية مشفرة وثابتة داخل الكود المصدري
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_API_KEY = "sk_test_51M000000000000000000000000000000"
JWT_SECRET = "super_insecure_jwt_secret_key_12345"
DATABASE_PASSWORD = "AdminPassword2026!"

app = FastAPI(title="Vulnerable Benchmark Application", docs_url="/docs", redoc_url=None)

# ==============================================================================
# 2. CORS MISCONFIGURATION
# ==============================================================================
# إعدادات CORS كارثية: السماح لجميع النطاقات (*) مع تفعيل Credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# إنشاء قاعدة بيانات SQLite في الذاكرة لتجربة الـ SQL Injection
def init_db():
    conn = sqlite3.connect("test_vulnerable.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, email TEXT, secret_note TEXT)")
    cursor.execute("DELETE FROM users")
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'administrator', 'admin@target.local', 'TOP_SECRET_FLAG{sql_injection_success}')")
    cursor.execute("INSERT INTO users VALUES (2, 'john_doe', 'user', 'john@target.local', 'My secret pass is 1234')")
    cursor.execute("INSERT INTO users VALUES (3, 'alice', 'user', 'alice@target.local', 'Vacation plan in Paris')")
    conn.commit()
    conn.close()

init_db()

# ==============================================================================
# MIDDLEWARE: MISSING SECURITY HEADERS & SERVER BANNER DISCLOSURE
# ==============================================================================
# لا توجد ترويسات أمان (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
# مع تسريب إصدار السيرفر والتقنيات عبر Server و X-Powered-By
@app.middleware("http")
async def add_vulnerable_headers(request: Request, call_next):
    response: Response = await call_next(request)
    # تسريب معلومات السيرفر
    response.headers["Server"] = "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1d"
    response.headers["X-Powered-By"] = "PHP/7.4.3"
    # تعمد عدم وجود:
    # - Strict-Transport-Security (HSTS)
    # - Content-Security-Policy (CSP)
    # - X-Frame-Options (Clickjacking vulnerability)
    # - X-Content-Type-Options: nosniff
    return response

# ==============================================================================
# 3. HOME PAGE (Crawling Entrypoint + DOM-XSS + Forms)
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
async def index_page(response: Response):
    # تعيين كوكيز غير آمنة (Missing HttpOnly, Missing Secure, Missing SameSite)
    response.set_cookie(
        key="session_token",
        value="insecure_session_token_xyz_98765",
        httponly=False,  # ثغرة: يمكن قراءته عبر JavaScript document.cookie
        secure=False,    # ثغرة: يُرسل عبر HTTP غير المشفر
        samesite=None    # ثغرة: معرض لهجمات CSRF
    )
    
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Vulnerable Target Web Application</title>
        <style>
            body { font-family: sans-serif; margin: 30px; background: #f4f6f9; color: #333; }
            h1 { color: #d9534f; }
            .card { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            input[type="text"], input[type="file"] { padding: 8px; width: 300px; margin-right: 10px; }
            button { padding: 8px 16px; background: #0275d8; color: white; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background: #025aa5; }
            .endpoints a { display: inline-block; margin-right: 15px; margin-bottom: 8px; color: #0275d8; text-decoration: none; }
        </style>
    </head>
    <body>
        <h1>🛡️ Vulnerable Benchmark Testbed (CyberAI Target)</h1>
        <p>This web application contains deliberate security vulnerabilities for SAST & DAST vulnerability scanners evaluation.</p>

        <div class="card">
            <h3>1. Reflected Cross-Site Scripting (XSS)</h3>
            <form action="/search" method="GET">
                <input type="text" name="q" placeholder="Search keyword..." value="test">
                <button type="submit">Search</button>
            </form>
        </div>

        <div class="card">
            <h3>2. SQL Injection (Error-Based & Time-Based)</h3>
            <form action="/api/user" method="GET">
                <input type="text" name="id" placeholder="User ID (e.g. 1 or 1' OR 1=1--)" value="1">
                <button type="submit">Query User</button>
            </form>
        </div>

        <div class="card">
            <h3>3. OS Command Injection (RCE)</h3>
            <form action="/ping" method="GET">
                <input type="text" name="host" placeholder="Hostname (e.g. 127.0.0.1 or 127.0.0.1; whoami)" value="127.0.0.1">
                <button type="submit">Ping Host</button>
            </form>
        </div>

        <div class="card">
            <h3>4. Server-Side Request Forgery (SSRF)</h3>
            <form action="/fetch" method="GET">
                <input type="text" name="url" placeholder="http://169.254.169.254/latest/meta-data/" value="http://httpbin.org/get">
                <button type="submit">Fetch URL</button>
            </form>
        </div>

        <div class="card">
            <h3>5. Server-Side Template Injection (SSTI)</h3>
            <form action="/render" method="GET">
                <input type="text" name="template" placeholder="Hello {{ 7*7 }}" value="Hello {{ 7*7 }}">
                <button type="submit">Render</button>
            </form>
        </div>

        <div class="card">
            <h3>6. Local File Inclusion (LFI / Path Traversal)</h3>
            <form action="/view" method="GET">
                <input type="text" name="file" placeholder="test.txt or ../../../../windows/win.ini" value="sample.txt">
                <button type="submit">Read File</button>
            </form>
        </div>

        <div class="card">
            <h3>7. Unrestricted File Upload</h3>
            <form action="/upload" method="POST" enctype="multipart/form-data">
                <input type="file" name="file">
                <button type="submit">Upload Shell/Script</button>
            </form>
        </div>

        <div class="card endpoints">
            <h3>Direct Links for Crawler Discovery</h3>
            <a href="/redirect?url=https://attacker.example.com">🔗 Open Redirect Test</a>
            <a href="/api/profile/1">🔗 IDOR User 1 (Admin)</a>
            <a href="/api/profile/2">🔗 IDOR User 2</a>
            <a href="/.env">🔗 Leaked .env file</a>
            <a href="/robots.txt">🔗 Exposed robots.txt</a>
            <a href="/insecure-deserialization?data=gASVBQAAAAAAAACMCXN5c3RlbS4uLg==">🔗 Insecure Deserialization (Pickle)</a>
            <a href="/weak-hash?text=admin">🔗 Weak MD5 Hash</a>
        </div>

        <!-- 8. DOM XSS & Client-side Exposed Keys -->
        <script>
            // تسريب مفاتيح داخل كود الجافاسكربت المفحوص
            window.AWS_CLIENT_SECRET = "AKIAIOSFODNN7EXAMPLE";
            window.STRIPE_PUBLIC_KEY = "pk_test_51M000000000000000000000000000000";

            // ثغرة DOM-XSS: استخدام sink خطير (document.write / location.hash)
            if (window.location.hash) {
                document.write("<p>Current hash: " + window.location.hash + "</p>");
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# ==============================================================================
# 4. SENSITIVE FILES EXPOSURE
# ==============================================================================
@app.get("/.env", response_class=PlainTextResponse)
async def leaked_env():
    # ثغرة كشف ملف البيئة .env المحتوي على كلمات سر واتصال بقاعدة البيانات
    return """
DB_HOST=127.0.0.1
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=SuperSecretPass123!
SECRET_KEY=supersecretjwtkey_cyberai_test_2026
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_test_51M000000000000000000000000000000
    """.strip()

@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
    # ثغرة كشف مسارات حساسة وغير مفهرسة
    return """
User-agent: *
Disallow: /admin
Disallow: /secret-backup
Disallow: /api/internal/
Disallow: /database.sqlite
    """.strip()

# ==============================================================================
# 5. REFLECTED CROSS-SITE SCRIPTING (XSS)
# ==============================================================================
@app.get("/search", response_class=HTMLResponse)
async def search(q: str = ""):
    # ثغرة Reflected XSS: إرجاع نص البحث مباشرة بدون HTML escaping أو sanitization
    return f"""
    <html>
        <body>
            <h2>Search Results</h2>
            <p>You searched for: {q}</p>
            <hr>
            <p>No results found for {q}.</p>
            <a href="/">Back to Home</a>
        </body>
    </html>
    """

# ==============================================================================
# 6. SQL INJECTION (ERROR-BASED & TIME-BASED)
# ==============================================================================
@app.get("/api/user")
async def get_user_sqli(id: str = "1"):
    conn = sqlite3.connect("test_vulnerable.db")
    cursor = conn.cursor()
    # ثغرة SQLi فادحة: دمج مدخل المستخدم id مباشرة في جملة الاستعلام (Raw String Concatenation)
    query = f"SELECT id, username, role, email FROM users WHERE id = {id}"
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        return {"status": "success", "query": query, "data": rows}
    except Exception as e:
        # ثغرة تسريب أخطاء قاعدة البيانات المفصلة (SQL Error Disclosure)
        # تساعد المهاجم على معرفة بنية الجداول ونوع المحرك
        conn.close()
        return JSONResponse(
            status_code=500,
            content={
                "error": "Database Operational Error",
                "details": f"sqlite3.OperationalError: {str(e)}",
                "failed_query": query,
                "syntax_message": "You have an error in your SQL syntax; check the manual that corresponds to your SQLite server version"
            }
        )

# ==============================================================================
# 7. OS COMMAND INJECTION (RCE)
# ==============================================================================
@app.get("/ping")
async def ping_host(host: str = "127.0.0.1"):
    # ثغرة حقن أوامر نظام التشغيل: تمرير المتغير إلى shell=True مباشرة
    # تمكن المهاجم من تنفيذ أوامر مثل: 127.0.0.1 && whoami
    try:
        cmd = f"ping -n 1 {host}" if os.name == "nt" else f"ping -c 1 {host}"
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, timeout=5)
        return PlainTextResponse(output)
    except subprocess.CalledProcessError as e:
        return PlainTextResponse(f"Command Error:\n{e.output}")
    except Exception as e:
        return PlainTextResponse(f"Error executing command: {str(e)}")

# ==============================================================================
# 8. SERVER-SIDE REQUEST FORGERY (SSRF)
# ==============================================================================
@app.get("/fetch")
async def ssrf_fetch(url: str = "http://127.0.0.1:5050/robots.txt"):
    # ثغرة SSRF: قيام السيرفر بطلب أي رابط يرسله العميل دون التحقق من الـ IP أو البروتوكول
    # يتيح الوصول لشبكة السيرفر الداخلية والـ Cloud Metadata (169.254.169.254)
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            res = await client.get(url)
            return PlainTextResponse(f"Fetched Status: {res.status_code}\n\nHeaders:\n{res.headers}\n\nBody:\n{res.text[:1000]}")
    except Exception as e:
        return PlainTextResponse(f"SSRF Request Failed: {str(e)}")

# ==============================================================================
# 9. SERVER-SIDE TEMPLATE INJECTION (SSTI)
# ==============================================================================
@app.get("/render", response_class=HTMLResponse)
async def ssti_render(template: str = "Hello {{ 7*7 }}"):
    # ثغرة SSTI: تمرير مدخلات المستخدم مباشرة إلى محرك القوالب
    # تمكن المهاجم من استدعاء الدوال الداخلية وتجاوز الساندبوكس لتنفيذ أوامر
    try:
        if jinja2:
            tmpl = jinja2.Environment().from_string(template)
            rendered = tmpl.render()
        else:
            # Fallback template evaluation for SSTI demonstration without needing jinja2 package
            import re
            def eval_expr(match):
                try:
                    return str(eval(match.group(1), {"__builtins__": __builtins__}))
                except Exception as ex:
                    return f"Error: {ex}"
            rendered = re.sub(r'\{\{\s*(.*?)\s*\}\}', eval_expr, template)
        return f"<h3>Rendered Output:</h3><div>{rendered}</div><br><a href='/'>Back</a>"
    except Exception as e:
        return f"<h3>Template Error:</h3><pre>{str(e)}</pre>"

# ==============================================================================
# 10. LOCAL FILE INCLUSION (LFI / PATH TRAVERSAL)
# ==============================================================================
@app.get("/view")
async def lfi_read(file: str = "sample.txt"):
    # ثغرة Path Traversal / LFI: قراءة الملفات مباشرة بدون التأكد من المسار
    # يسمح بمدخلات مثل ../../../../etc/passwd أو ../../../../windows/win.ini
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        target_path = os.path.join(base_dir, file)
        
        # إذا لم يكن الملف موجوداً، ننشئ ملفاً تجريبياً
        if file == "sample.txt" and not os.path.exists(target_path):
            with open(target_path, "w") as f:
                f.write("This is a safe sample file content.")

        with open(target_path, "r", errors="ignore") as f:
            content = f.read()
        return PlainTextResponse(f"File Content of '{file}':\n\n{content}")
    except Exception as e:
        return PlainTextResponse(f"Error reading file '{file}': {str(e)}")

# ==============================================================================
# 11. UNRESTRICTED FILE UPLOAD
# ==============================================================================
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    # ثغرة رفع ملفات دون قيود:
    # 1. لا يتم فحص الامتداد (يقبل .php, .exe, .sh, .html, .svg)
    # 2. لا يتم فحص نوع الملف الحقيقي (MIME-type / Magic Bytes)
    # 3. يُحفظ باسمه الأصلي في مسار يمكن الوصول إليه
    destination = os.path.join(UPLOAD_DIR, file.filename)
    with open(destination, "wb") as buffer:
        buffer.write(await file.read())
    return {
        "status": "success",
        "message": f"File '{file.filename}' uploaded successfully without any security validation!",
        "file_path": destination
    }

# ==============================================================================
# 12. BROKEN OBJECT LEVEL AUTHORIZATION (IDOR / BOLA)
# ==============================================================================
@app.get("/api/profile/{user_id}")
async def get_user_profile(user_id: int):
    # ثغرة IDOR: عرض بيانات أي مستخدم بناءً على المعرف في الرابط بدون مصادقة أو تحقق
    conn = sqlite3.connect("test_vulnerable.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, email, secret_note FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return JSONResponse(status_code=404, content={"error": "User not found"})
    return {
        "user_id": row[0],
        "username": row[1],
        "role": row[2],
        "email": row[3],
        "sensitive_data": row[4] # تسريب أسرار المستخدمين للعامة
    }

# ==============================================================================
# 13. OPEN REDIRECT
# ==============================================================================
@app.get("/redirect")
async def open_redirect(url: str = "https://example.com"):
    # ثغرة التوجيه المفتوح: إعادة توجيه المستخدم لأي نطاق خارجي دون قائمة بيضاء
    return RedirectResponse(url=url, status_code=302)

# ==============================================================================
# 14. INSECURE DESERIALIZATION (PICKLE) - SAST & RCE
# ==============================================================================
@app.get("/insecure-deserialization")
async def insecure_pickle(data: str = ""):
    # ثغرة فك التسلسل غير الآمن باستخدام مكتبة pickle
    # تسمح بتنفيذ كود عشوائي RCE عبر حمولات الكائنات الخبيثة
    if not data:
        return PlainTextResponse("Send base64 or pickled data in ?data=")
    try:
        import base64
        decoded = base64.b64decode(data)
        # خطر SAST: استخدام pickle.loads على بيانات غير موثوقة
        obj = pickle.loads(decoded)
        return {"status": "unpickled", "object": str(obj)}
    except Exception as e:
        return PlainTextResponse(f"Deserialization error: {str(e)}")

# ==============================================================================
# 15. WEAK CRYPTOGRAPHY (MD5 HASHING) - SAST
# ==============================================================================
@app.get("/weak-hash")
async def weak_hash(text: str = "password"):
    # ثغرة تشفير ضعيف: استخدام MD5 لتشفير كلمات المرور أو البيانات الحساسة
    hasher = hashlib.md5() # flagged by SAST / Bandit (B303/B324)
    hasher.update(text.encode("utf-8"))
    return {"algorithm": "MD5", "input": text, "digest": hasher.hexdigest()}

# ==============================================================================
# 16. INSECURE EVAL / DYNAMIC CODE EXECUTION
# ==============================================================================
@app.get("/calc")
async def insecure_eval(expr: str = "2+2"):
    # ثغرة استخدام eval() الخطيرة: تنفيذ كود بايثون مباشر من المستخدم
    try:
        result = eval(expr) # flagged by SAST / Bandit (B307)
        return {"expression": expr, "result": result}
    except Exception as e:
        return PlainTextResponse(f"Eval Error: {str(e)}")

# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================
if __name__ == "__main__":
    print("=" * 70)
    print("[+] Running Vulnerable Target Test Application on http://127.0.0.1:5050")
    print("[+] Target URL to scan (e.g. CyberAI): http://127.0.0.1:5050")
    print("=" * 70)
    uvicorn.run(app, host="127.0.0.1", port=5050)
