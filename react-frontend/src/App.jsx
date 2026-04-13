import { useEffect, useState } from "react";

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // On every page load, ask the backend if we have a valid session.
    // The browser automatically sends the HttpOnly cookie with this request
    // (credentials: "include" is required for cross-origin fetches).
    // We never read the cookie directly — JS can't, because it's HttpOnly.
    fetch("/api/auth/me", { credentials: "include" })
      .then((res) => {
        if (res.ok) return res.json();
        return null; // 401 = not authenticated
      })
      .then((data) => {
        if (data?.authenticated) setUser(data.user_id);
      })
      .finally(() => setLoading(false));
  }, []);

  const login = () => {
    window.location.href = "/api/login";
  };

  const logout = () => {
    // /api/slo redirects to IdP to kill the IdP session too.
    // Use /api/logout instead if you only want local cookie cleared.
    window.location.href = "/api/slo";
  };

  if (loading) return <div style={{ padding: 40 }}>Checking session...</div>;

  return (
    <div style={{ padding: 40 }}>
      <h1>SAML POC</h1>

      {!user ? (
        <button onClick={login}>Login with SAML</button>
      ) : (
        <div>
          <h2>Logged in as: {user}</h2>
          <button onClick={logout}>Logout</button>
        </div>
      )}
    </div>
  );
}

export default App;