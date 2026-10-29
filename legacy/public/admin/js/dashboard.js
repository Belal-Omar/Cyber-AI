document.addEventListener('DOMContentLoaded', async () => {

  const token = localStorage.getItem('adminToken');

  if (!token) {

    window.location.href = '/admin/login';

    return;

  }

  const $ = (id) => document.getElementById(id);

  const navAdminName = $('navAdminName');

  const logoutBtn = $('logoutBtn');

  async function apiFetch(url, options = {}) {

    const response = await fetch(url, {

      ...options,

      headers: {

        'Content-Type': 'application/json',

        ...options.headers,

        Authorization: `Bearer ${token}`,

      },

    });

    // An expired or invalid session requires login again.

    if (response.status === 401) {

      localStorage.removeItem('adminToken');

      localStorage.removeItem('adminUser');

      window.location.href = '/admin/login';

      throw new Error('Session expired. Please log in again.');

    }

    const data = await response.json();

    if (!response.ok || data.success === false) {

      throw new Error(data.error || 'Request failed.');

    }

    return data;

  }

  function showError(tbodyId, columns, message) {

    const tbody = $(tbodyId);

    if (!tbody) return;

    const row = document.createElement('tr');

    const cell = document.createElement('td');

    cell.colSpan = columns;

    cell.className = 'dashboard-empty';

    cell.textContent = message;

    row.appendChild(cell);

    tbody.replaceChildren(row);

  }

  function addCell(row, value) {

    const cell = document.createElement('td');

    cell.textContent = value ?? '—';

    row.appendChild(cell);

    return cell;

  }

  function formatDate(value) {

    if (!value) return 'Never';

    const date = new Date(value);

    return Number.isNaN(date.getTime())

      ? '—'

      : date.toLocaleString();

  }

  function showMessage(message) {

    window.alert(message);

  }

  // Verify the current administrator.

  try {

    const data = await apiFetch('/api/admin/me');

    if (navAdminName && data.user) {

      navAdminName.textContent = data.user.name;

    }

    await Promise.all([

      loadStats(),

      loadUsers(),

      loadAuditLogs(),

    ]);

  } catch (error) {

    console.error('Dashboard initialization error:', error);

  }

  // Load dashboard statistics.

  async function loadStats() {

    try {

      const data = await apiFetch('/api/admin/stats');

      const stats = data.stats || {};

      if ($('totalAdmin')) {

        $('totalAdmin').textContent = stats.totalAdmin ?? 0;

      }

      if ($('totalTargets')) {

        $('totalTargets').textContent = stats.totalTargets ?? 0;

      }

      if ($('totalScans')) {

        $('totalScans').textContent = stats.totalScans ?? 0;

      }

      const usersData = await apiFetch('/api/admin/users');

      const admins = (usersData.users || []).filter(

        (user) => String(user.role).toUpperCase() === 'ADMIN'

      );

      if ($('totalAdmins')) {

        $('totalAdmins').textContent = admins.length;

      }

    } catch (error) {

      console.error('Stats loading error:', error);

    }

  }

  // Activate or deactivate a user.

  async function changeUserStatus(user, button) {

    const nextStatus = !user.isActive;

    const action = nextStatus ? 'activate' : 'deactivate';

    const confirmed = window.confirm(

      `Are you sure you want to ${action} the account for ${user.name} (${user.email})?`

    );

    if (!confirmed) return;

    button.disabled = true;

    const originalText = button.textContent;

    button.textContent = 'Updating...';

    try {

      const result = await apiFetch(

        `/api/admin/users/${encodeURIComponent(user.id)}/status`,

        {

          method: 'PATCH',

          body: JSON.stringify({

            isActive: nextStatus,

          }),

        }

      );

      showMessage(

        result.message ||

          `User ${nextStatus ? 'activated' : 'deactivated'} successfully.`

      );

      // Reload the affected dashboard sections.

      await Promise.all([

        loadUsers(),

        loadStats(),

        loadAuditLogs(),

      ]);

    } catch (error) {

      console.error('Update user status error:', error);

      showMessage(error.message || 'Unable to update user status.');

      button.disabled = false;

      button.textContent = originalText;

    }

  }

  // Load users from the database.

  async function loadUsers() {

    const tbody = $('usersTableBody');

    if (!tbody) return;

    try {

      tbody.textContent = '';

      const data = await apiFetch('/api/admin/users');

      const users = data.users || [];

      if (users.length === 0) {

        showError('usersTableBody', 6, 'No users found.');

        return;

      }

      users.forEach((user) => {

        const row = document.createElement('tr');

        addCell(row, user.name);

        addCell(row, user.email);

        const roleCell = document.createElement('td');

        const roleBadge = document.createElement('span');

        roleBadge.className =

          String(user.role).toUpperCase() === 'ADMIN'

            ? 'tag-admin'

            : 'tag-user';

        roleBadge.textContent = user.role || 'USER';

        roleCell.appendChild(roleBadge);

        row.appendChild(roleCell);

        const statusCell = document.createElement('td');

        const statusBadge = document.createElement('span');

        statusBadge.className = user.isActive

          ? 'pill-active'

          : 'tag-user';

        statusBadge.textContent = user.isActive

          ? '● Active'

          : 'Inactive';

        statusCell.appendChild(statusBadge);

        row.appendChild(statusCell);

        addCell(row, formatDate(user.lastLoginAt));

        // Actions column.

        const actionCell = document.createElement('td');

        const actionButton = document.createElement('button');

        actionButton.type = 'button';

        actionButton.className = user.isActive

          ? 'user-action-btn deactivate-btn'

          : 'user-action-btn activate-btn';

        actionButton.textContent = user.isActive

          ? 'Deactivate'

          : 'Activate';

        actionButton.addEventListener('click', () => {

          changeUserStatus(user, actionButton);

        });

        actionCell.appendChild(actionButton);

        row.appendChild(actionCell);

        tbody.appendChild(row);

      });

    } catch (error) {

      console.error('Users loading error:', error);

      showError('usersTableBody', 6, 'Unable to load users.');

    }

  }

  // Load recent audit activity.

  async function loadAuditLogs() {

    const tbody = $('auditLogsTableBody');

    if (!tbody) return;

    try {

      tbody.textContent = '';

      const data = await apiFetch('/api/admin/audit-logs');

      const logs = data.logs || [];

      if (logs.length === 0) {

        showError('auditLogsTableBody', 4, 'No audit logs found.');

        return;

      }

      logs.forEach((log) => {

        const row = document.createElement('tr');

        addCell(row, log.action);

        addCell(

          row,

          log.user?.name || log.user?.email || 'System'

        );

        addCell(row, formatDate(log.createdAt));

        addCell(row, log.details || '—');

        tbody.appendChild(row);

      });

    } catch (error) {

      console.error('Audit logs loading error:', error);

      showError('auditLogsTableBody', 4, 'Unable to load audit logs.');

    }

  }

  // Refresh buttons.

  $('refreshUsersBtn')?.addEventListener('click', loadUsers);

  $('refreshLogsBtn')?.addEventListener('click', loadAuditLogs);

  // Sign out.

  logoutBtn?.addEventListener('click', async () => {

    logoutBtn.disabled = true;

    try {

      await fetch('/api/admin/logout', {

        method: 'POST',

        headers: {

          Authorization: `Bearer ${token}`,

        },

      });

    } catch (error) {

      console.error('Logout request error:', error);

    } finally {

      localStorage.removeItem('adminToken');

      localStorage.removeItem('adminUser');

      window.location.href = '/admin/login';
    }
  });
});