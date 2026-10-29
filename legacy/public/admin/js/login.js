document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('adminLoginForm');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const togglePasswordBtn = document.getElementById('togglePasswordBtn');
  const submitBtn = document.getElementById('submitBtn');
  const btnText = document.getElementById('btnText');
  const btnSpinner = document.getElementById('btnSpinner');
  const alertBox = document.getElementById('alertBox');
  const alertText = document.getElementById('alertText');

  // Toggle password visibility

  // Show Alert Box
  function showAlert(message, type = 'danger') {
    alertBox.className = `alert-box alert-${type}`;
    alertBox.style.display = 'flex';
    alertText.innerHTML = message;
  }

  function hideAlert() {
    alertBox.style.display = 'none';
  }

  // Handle Form Submission
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const email = emailInput.value.trim();
    const password = passwordInput.value;

    if (!email || !password) {
      showAlert('Please enter both email and password.', 'danger');
      return;
    }

    // Set Loading State
    submitBtn.disabled = true;
    btnText.textContent = 'Verifying credentials...';
    btnSpinner.style.display = 'inline-block';

    try {
      const response = await fetch('/api/admin/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        // Successful login with role = ADMIN
        showAlert(`<strong>Authentication successful!</strong> Welcome Admin ${data.user.name}. Redirecting...`, 'success');

        // Store JWT token and admin info in localStorage
        localStorage.setItem('adminToken', data.token);
        localStorage.setItem('adminUser', JSON.stringify(data.user));

        setTimeout(() => {
          window.location.href = '/admin/dashboard';
        }, 800);
      } else {
        // Role check failed (403) or Invalid credentials (401)
        const errorMsg = data.error || 'Authentication failed. Please verify your credentials.';
        showAlert(`⛔ ${errorMsg}`, 'danger');
      }
    } catch (err) {
      console.error('Login error:', err);
      showAlert('⚠️ Server connection error. Please ensure XAMPP MySQL and backend server are running.', 'danger');
    } finally {
      submitBtn.disabled = false;
      btnText.textContent = 'Log in to Admin Portal';
      btnSpinner.style.display = 'none';
    }
  });
});
