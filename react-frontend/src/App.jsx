import { Routes, Route, Navigate } from "react-router-dom";
import { useEffect, useState } from "react";
import LoginPage from "./pages/LoginPage";
import HomePage from "./pages/HomePage";

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const u = params.get("user");
    if (u) {
      setUser(u);
      window.history.replaceState({}, "", "/");
    }
    setLoading(false);
  }, []);

  const handleLogin = () => {
    window.location.href = "/api/login";
  };

  const handleLogout = () => {
    setUser(null);
    window.location.href = "/";
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-muted via-background to-muted">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  return (
    <Routes>
      <Route
        path="/"
        element={user ? <Navigate to="/home" replace /> : <LoginPage />}
      />
      <Route
        path="/home"
        element={user ? <HomePage user={user} onLogout={handleLogout} /> : <Navigate to="/" replace />}
      />
    </Routes>
  );
}

export default App;