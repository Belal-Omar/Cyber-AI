
// SentinelAI - Main Page JavaScript

document.addEventListener("DOMContentLoaded", () => {
    console.log("SentinelAI Home Page is ready!");

    // 1. Navigation: Login
    const loginLink = document.querySelector(".login-link");

    if (loginLink) {
        loginLink.addEventListener("click", (event) => {
            event.preventDefault();
            window.location.href = "login.html";
        });
    }

    // 2. Navigation: Start Free
    const startFreeButton = document.querySelector(
        ".nav-actions .btn-primary"
    );

    if (startFreeButton) {
        startFreeButton.addEventListener("click", (event) => {
            event.preventDefault();
            window.location.href = "signup.html";
        });
    }

    // 3. Navigation: Start First Scan
    const buttons = document.querySelectorAll(".hero-buttons a");

    if (buttons.length > 0) {
        buttons[0].addEventListener("click", (event) => {
            event.preventDefault();

            const token =
                localStorage.getItem("token") ||
                sessionStorage.getItem("token");

            if (token) {
                window.location.href = "dashboard.html";
            } else {
                alert("Please log in to start a security assessment.");
                window.location.href = "login.html";
            }
        });
    }

    // 4. Navigation: View Dashboard
    if (buttons.length > 1) {
        buttons[1].addEventListener("click", (event) => {
            event.preventDefault();

            const token =
                localStorage.getItem("token") ||
                sessionStorage.getItem("token");

            if (token) {
                window.location.href = "dashboard.html";
            } else {
                alert("Please log in to view your dashboard.");
                window.location.href = "login.html";
            }
        });
    }

    // 5. Read saved user information
    const savedUser =
        localStorage.getItem("user") ||
        sessionStorage.getItem("user");

    if (savedUser) {
        try {
            const user = JSON.parse(savedUser);
            console.log("Saved user information:", user);
        } catch (error) {
            console.error("Could not read saved user information.");
        }
    }
});
document.addEventListener("DOMContentLoaded", () => {
    // 1. قراءة الـ Token وبيانات المستخدم من localStorage
    const token = localStorage.getItem("token");
    const user = JSON.parse(localStorage.getItem("user") || "null");

    // عناصر الواجهة (تأكدي من مطابقة الأي دي أو الكلاس للـ HTML عندك)
    const loginBtn = document.querySelector('a[href*="login"], .login-btn'); 
    const startScanBtn = document.querySelector('.start-scan-btn'); // زرار Start your first scan
    const dashboardBtn = document.querySelector('.view-dashboard-btn'); // زرار View dashboard

    // 2. التحقق من حالة تسجيل الدخول
    if (token && user) {
        // لو مسجل دخول: غير نص زرار الـ Log in لإظهار الاسم أو الخروج
        if (loginBtn) {
            loginBtn.textContent = `Welcome, ${user.name || 'User'}`;
            loginBtn.href = "#"; // أو توجيه لصفحة البروفايل
        }
    }

    // 3. التوجيه عند الضغط على Start your first scan
    if (startScanBtn) {
        startScanBtn.addEventListener("click", (e) => {
            e.preventDefault();
            if (token) {
                // لو مسجل دخول يروح لصفحة الفحص أو الـ Dashboard
                window.location.href = "/dashboard.html";
            } else {
                // لو مش مسجل يروح لصفحة اللوجن الأول
                window.location.href = "/login.html";
            }
        });
    }

    // 4. التوجيه عند الضغط على View dashboard
    if (dashboardBtn) {
        dashboardBtn.addEventListener("click", (e) => {
            e.preventDefault();
            if (token) {
                window.location.href = "/dashboard.html";
            } else {
                window.location.href = "/login.html";
            }
        });
    }
});

// 5. دالة مساعدة لتسجيل الخروج (ممكن تستخدميها)
function logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    window.location.reload();
}
// Logout Logic
document.addEventListener('DOMContentLoaded', () => {
    const logoutBtn = document.getElementById('logoutBtn');
    const loginBtn = document.querySelector('.login-btn:not(#logoutBtn)');
    const token = localStorage.getItem('token');

    // لو المستخدم مسجل دخول بالفعل
    if (token) {
        if (loginBtn) loginBtn.style.display = 'none';
        if (logoutBtn) logoutBtn.style.display = 'inline-block';
    } else {
        if (loginBtn) loginBtn.style.display = 'inline-block';
        if (logoutBtn) logoutBtn.style.display = 'none';
    }

    // عند الضغط على Logout
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.href = 'login.html';
        });
    }
});
