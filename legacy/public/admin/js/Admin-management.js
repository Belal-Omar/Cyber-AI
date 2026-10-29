document.addEventListener('DOMContentLoaded', async function () {

    const token = localStorage.getItem('adminToken');

    if (!token) {

        window.location.href = '/admin/login';

        return;

    }

    const tbody = document.getElementById('usersTableBody');

    const refreshBtn = document.getElementById('refreshUsersBtn');

    const message = document.getElementById('usersMessage');

    async function apiFetch(url, options = {}) {

        const response = await fetch(url, {

            ...options,

            headers: {

                'Content-Type': 'application/json',

                ...options.headers,

                Authorization: 'Bearer ' + token

            }

        });

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

    function showMessage(text, isError) {

        if (!message) return;

        message.textContent = text;

        message.style.color = isError ? 'red' : 'green';

    }

    function addCell(row, value) {

        const cell = document.createElement('td');

        cell.textContent = value == null ? '—' : String(value);

        row.appendChild(cell);

    }

    function formatDate(value) {

        if (!value) return 'Never';

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {

            return '—';

        }

        return date.toLocaleString();

    }

    async function changeUserStatus(user, button) {

        const nextStatus = !user.isActive;

        const action = nextStatus ? 'activate' : 'deactivate';

        const confirmed = window.confirm(

            'Are you sure you want to ' + action + ' ' +

            user.name + ' (' + user.email + ')?'

        );

        if (!confirmed) return;

        button.disabled = true;

        button.textContent = 'Updating...';

        try {

            const result = await apiFetch(

                '/api/admin/users/' +

                encodeURIComponent(user.id) + '/status',

                {

                    method: 'PATCH',

                    body: JSON.stringify({

                        isActive: nextStatus

                    })

                }

            );

            showMessage(

                result.message || 'User status updated successfully.',

                false

            );

            await loadUsers();

        } catch (error) {

            console.error('Update user status error:', error);

            showMessage(

                error.message || 'Unable to update user status.',

                true

            );

            button.disabled = false;

            button.textContent = user.isActive

                ? 'Deactivate'

                : 'Activate';

        }

    }

    async function loadUsers() {

        if (!tbody) {

            console.error('usersTableBody was not found in the HTML.');

            return;

        }

        tbody.replaceChildren();

        const loadingRow = document.createElement('tr');

        const loadingCell = document.createElement('td');

        loadingCell.colSpan = 6;

        loadingCell.textContent = 'Loading users...';

        loadingRow.appendChild(loadingCell);

        tbody.appendChild(loadingRow);

        try {
const data = await apiFetch('/api/admin/users');

const users = (data.users || []).filter(
    user => user.role === 'ADMIN'
);
           

            tbody.replaceChildren();

            if (users.length === 0) {

                const row = document.createElement('tr');

                const cell = document.createElement('td');

                cell.colSpan = 6;

                cell.textContent = 'No users found.';

                row.appendChild(cell);tbody.appendChild(row);

                return;

            }

            users.forEach(function (user) {

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

                    ? 'Active'

                    : 'Inactive';

                statusCell.appendChild(statusBadge);

                row.appendChild(statusCell);

                addCell(row, formatDate(user.lastLoginAt));

                const actionCell = document.createElement('td');

                const actionButton = document.createElement('button');

                actionButton.type = 'button';

                actionButton.className = user.isActive

                    ? 'user-action-btn deactivate-btn'

                    : 'user-action-btn activate-btn';

                actionButton.textContent = user.isActive

                    ? 'Deactivate'

                    : 'Activate';

                actionButton.addEventListener('click', function () {

                    changeUserStatus(user, actionButton);

                });

                actionCell.appendChild(actionButton);

                row.appendChild(actionCell);

                tbody.appendChild(row);

            });

        } catch (error) {

            console.error('Load users error:', error);

            tbody.replaceChildren();

            const row = document.createElement('tr');

            const cell = document.createElement('td');

            cell.colSpan = 6;

            cell.textContent = 'Unable to load users.';

            row.appendChild(cell);

            tbody.appendChild(row);

            showMessage(

                error.message || 'Unable to load users.',

                true

            );

        }

    }

    if (refreshBtn) {

        refreshBtn.addEventListener('click', loadUsers);

    }

    try {

        await apiFetch('/api/admin/me');

        await loadUsers();

    } catch (error) {

        console.error('Admin Management initialization error:', error);

    }

});