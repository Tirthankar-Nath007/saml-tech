import { Shield, LogOut } from "lucide-react";
import { Button } from "../components/ui/button";
import logo from "../assets/tvscredit-logo.png";

const HomePage = ({ user, onLogout }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-muted via-background to-muted p-4">
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-96 h-96 rounded-full bg-tvs-blue/5" />
        <div className="absolute -bottom-40 -left-40 w-96 h-96 rounded-full bg-tvs-green/5" />
      </div>

      <div className="relative max-w-4xl mx-auto">
        <div className="bg-card rounded-2xl shadow-2xl shadow-tvs-blue/10 border border-border/60 overflow-hidden">
          <div className="h-1.5 w-full" style={{ background: "var(--tvs-gradient)" }} />

          <div className="px-8 py-12 flex flex-col items-center gap-8">
            <div className="flex flex-col items-center gap-3">
              <img src={logo} alt="TVS Credit Service Ltd" className="h-14 object-contain" />
              <p className="text-muted-foreground text-sm tracking-wide">
                SERVICE LTD
              </p>
            </div>

            <div className="bg-muted/50 rounded-lg px-4 py-2 w-full text-center">
              <span className="text-sm font-semibold text-tvs-blue tracking-wide uppercase">
                SAML SSO Portal
              </span>
            </div>

            <div className="text-center space-y-2">
              <h1 className="text-2xl font-bold text-foreground">
                Successfully Authenticated
              </h1>
              <p className="text-muted-foreground text-sm">
                You have logged in via SSO
              </p>
            </div>

            <div className="bg-primary/5 border border-primary/20 rounded-xl px-6 py-4 w-full max-w-md">
              <div className="flex items-center gap-3">
                <Shield className="h-8 w-8 text-tvs-blue" />
                <div className="text-left">
                  <p className="text-sm text-muted-foreground">Logged in as</p>
                  <p className="text-lg font-semibold text-foreground">{user}</p>
                </div>
              </div>
            </div>

            <Button
              onClick={onLogout}
              variant="outline"
              className="mt-4"
            >
              <LogOut className="mr-2 h-4 w-4" />
              Logout
            </Button>
          </div>
        </div>

        <p className="text-center text-xs text-muted-foreground mt-6">
          © {new Date().getFullYear()} TVS Credit Service Ltd. All rights reserved.
        </p>
      </div>
    </div>
  );
};

export default HomePage;