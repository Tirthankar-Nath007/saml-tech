import { Routes, Route, Navigate } from "react-router-dom";
import { useState } from "react";
import LoginPage from "./pages/LoginPage";
import HomePage from "./pages/HomePage";

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const checkAuth = async () => {
    try {
      const res = await fetch("/api/auth/me", { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        if (data.authenticated) {
          setUser(data.user_id);
        }
      }
    } catch (err) {
      console.error("Auth check failed:", err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    checkAuth();
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-muted via-background to-muted">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  const handleLogout = () => {
    setUser(null);
    window.location.href = "/api/logout";
  };

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