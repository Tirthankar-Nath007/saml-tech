import { useEffect, useState } from "react";

function App() {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const u = params.get("user");
    if (u) setUser(u);
  }, []);

  const login = () => {
    window.location.href = "/api/login";
  };

  return (
    <div style={{ padding: 40 }}>
      <h1>SAML POC</h1>

      {!user ? (
        <button onClick={login}>Login with SAML</button>
      ) : (
        <h2>Logged in as: {user}</h2>
      )}
    </div>
  );
}

export default App;