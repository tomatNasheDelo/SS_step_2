import React from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

const API = 'http://localhost:8080';
const TOKEN_KEY = 'learning-demo-rbac-jwt';
const ROLES_KEY = 'learning-demo-rbac-roles';
const USERNAME_KEY = 'learning-demo-rbac-username';

function App() {
  const [token, setToken] = React.useState(() => localStorage.getItem(TOKEN_KEY));
  const [roles, setRoles] = React.useState(() => JSON.parse(localStorage.getItem(ROLES_KEY) || '[]'));
  const [username, setUsername] = React.useState(() => localStorage.getItem(USERNAME_KEY) || 'student');
  const [password, setPassword] = React.useState('password123');
  const [message, setMessage] = React.useState('');
  const [error, setError] = React.useState('');
  const [status, setStatus] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const isAdmin = roles.includes('ADMIN');

  async function login(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setMessage('');
    setStatus('');
    try {
      const response = await fetch(`${API}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Не удалось войти. Проверьте логин и пароль.');
      localStorage.setItem(TOKEN_KEY, data.token);
      localStorage.setItem(ROLES_KEY, JSON.stringify(data.roles));
      localStorage.setItem(USERNAME_KEY, username);
      setToken(data.token);
      setRoles(data.roles);
      setPassword('');
      setMessage(`Вход выполнен. Ваша роль: ${data.roles.join(', ')}.`);
    } catch (cause) {
      setError(cause.message || 'Не удалось связаться с backend.');
    } finally {
      setBusy(false);
    }
  }

  async function request(path, label) {
    setBusy(true);
    setError('');
    setMessage('');
    setStatus('');
    try {
      const response = await fetch(`${API}${path}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await response.json().catch(() => ({}));
      setStatus(`HTTP ${response.status}`);
      if (!response.ok) {
        if (response.status === 401) {
          clearToken();
          throw new Error('Сессия истекла или токен недействителен. Войдите снова.');
        }
        if (response.status === 403) {
          setError(`Доступ запрещён (403 Forbidden). Роль ${roles.join(', ')} не разрешает это действие.`);
          return;
        }
        throw new Error(data.detail || data.message || `Ошибка сервера: ${response.status}`);
      }
      setMessage(`${label}: ${data.message} Пользователь: ${data.username}.`);
    } catch (cause) {
      setError(cause.message || 'Не удалось связаться с backend.');
    } finally {
      setBusy(false);
    }
  }

  function clearToken() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(ROLES_KEY);
    localStorage.removeItem(USERNAME_KEY);
    setToken(null);
    setRoles([]);
  }

  function logout() {
    clearToken();
    setMessage('Токен удалён из браузера.');
    setError('');
    setStatus('');
  }

  return (
    <main className="layout">
      <section className="card">
        <div className="badge"><span className="dot" /> ШАГ 2 · РОЛИ И ДОСТУП</div>
        <h1>Кто что может делать?</h1>
        <p className="intro">JWT содержит роли пользователя. Сервер проверяет права на каждом защищённом запросе.</p>

        {!token ? (
          <form onSubmit={login}>
            <label>Имя пользователя
              <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required />
            </label>
            <label>Пароль
              <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required />
            </label>
            <button disabled={busy}>{busy ? 'Проверяем…' : 'Войти'}</button>
          </form>
        ) : (
          <div className="workspace">
            <div className="identity">
              <div><span className="caption">ВЫ ВОШЛИ КАК</span><strong>{username}</strong></div>
              <div className="roles">{roles.map((role) => <span className={`role ${role.toLowerCase()}`} key={role}>{role}</span>)}</div>
            </div>
            <button className="regular" onClick={() => request('/api/hello', 'Обычный endpoint')} disabled={busy}>
              Вызвать endpoint для всех вошедших
            </button>
            {isAdmin ? (
              <button className="admin" onClick={() => request('/api/admin', 'Административный endpoint')} disabled={busy}>
                Открыть панель администратора
              </button>
            ) : (
              <button className="probe" onClick={() => request('/api/admin', 'Административный endpoint')} disabled={busy}>
                Проверить ответ сервера 403
              </button>
            )}
            {status && <span className="status">{status}</span>}
            <button className="secondary" onClick={logout} disabled={busy}>Выйти и удалить JWT</button>
          </div>
        )}

        {message && <p className="notice success" aria-live="polite">{message}</p>}
        {error && <p className="notice error" role="alert">{error}</p>}

        <div className="credentials">
          <strong>Демо-аккаунты</strong>
          <p><code>student</code> / <code>password123</code> → USER</p>
          <p><code>admin</code> / <code>admin123</code> → ADMIN</p>
        </div>
      </section>

      <aside className="side">
        <span className="side-label">ПРАВИЛА ДОСТУПА</span>
        <div className="rule"><span className="role user">USER</span><p>Обычные защищённые данные.</p></div>
        <div className="rule"><span className="role admin">ADMIN</span><p>Обычные данные и административный endpoint.</p></div>
        <div className="explain">
          <strong>Сервер — главный</strong>
          <p>React скрывает кнопку, но это только удобство интерфейса. Доступ реально проверяет backend через <code>@PreAuthorize</code>.</p>
        </div>
        <ol>
          <li>Войти как USER и нажать проверку 403.</li>
          <li>Выйти, войти как ADMIN и открыть панель.</li>
        </ol>
      </aside>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
