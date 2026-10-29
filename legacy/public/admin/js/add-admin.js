document.addEventListener('DOMContentLoaded', () => {

  const form = document.getElementById('addAdminForm');

  const message = document.getElementById('addAdminMessage');

  if (!form || !message) {

    console.error('Add Admin form was not found.');

    return;

  }

  form.addEventListener('submit', async (event) => {

    event.preventDefault();

    const name = document.getElementById('adminFullName').value.trim();

    const email = document.getElementById('adminEmail').value.trim();

    const password = document.getElementById('adminPassword').value;

    const confirmPassword = document.getElementById('adminConfirmPassword').value;

    message.textContent = '';

    message.style.color = '';

    if (password !== confirmPassword) {

      message.textContent = 'Passwords do not match.';

      message.style.color = 'red';

      return;

    }

    if (password.length < 8) {

      message.textContent = 'Password must be at least 8 characters.';

      message.style.color = 'red';

      return;

    }

    const token =

      localStorage.getItem('adminToken') ||

      localStorage.getItem('token') ||

      sessionStorage.getItem('adminToken') ||

      sessionStorage.getItem('token');

    if (!token) {

      message.textContent = 'Please log in again as an administrator.';

      message.style.color = 'red';

      return;

    }

    const submitButton = form.querySelector('button[type="submit"]');

    if (submitButton) {

      submitButton.disabled = true;

      submitButton.textContent = 'Creating...';

    }

    try {

      const response = await fetch('/api/admin/create-admin', {

        method: 'POST',

        headers: {

          'Content-Type': 'application/json',

          'Authorization': 'Bearer ' + token

        },

        body: JSON.stringify({

          name: name,

          email: email,

          password: password

        })

      });

      const result = await response.json();

      if (!response.ok || !result.success) {

        throw new Error(result.error || 'Failed to create admin.');

      }

      message.textContent = 'Success! Admin account created successfully.';

      message.style.color = 'green';

      form.reset();

    } catch (error) {

      console.error('Create Admin error:', error);

      message.textContent =

        error instanceof Error

          ? error.message

          : 'Something went wrong. Please try again.';

      message.style.color = 'red';

    } finally {

      if (submitButton) {

        submitButton.disabled = false;

        submitButton.textContent = 'Create Admin';
      }
}
});
});