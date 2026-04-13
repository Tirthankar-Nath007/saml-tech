import { Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import logo from "@/assets/tvscredit-logo.png";

const LoginPage = ({ projectTitle = "Project Portal" }) => {
  const handleSSOLogin = () => {
    window.location.href = "/api/login";
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-muted via-background to-muted p-4">
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-96 h-96 rounded-full bg-tvs-blue/5" />
        <div className="absolute -bottom-40 -left-40 w-96 h-96 rounded-full bg-tvs-green/5" />
      </div>

      <div className="relative w-full max-w-md">
        <div className="bg-card rounded-2xl shadow-2xl shadow-tvs-blue/10 border border-border/60 overflow-hidden">
          <div className="h-1.5 w-full" style={{ background: "var(--tvs-gradient)" }} />

          <div className="px-8 pt-10 pb-10 flex flex-col items-center gap-8">
            <div className="flex flex-col items-center gap-3">
              <img src={logo} alt="TVS Credit Service Ltd" className="h-14 object-contain" />
              <p className="text-muted-foreground text-sm tracking-wide">
                SERVICE LTD
              </p>
            </div>

            <div className="bg-muted/50 rounded-lg px-4 py-2 w-full text-center">
              <span className="text-sm font-semibold text-tvs-blue tracking-wide uppercase">
                {projectTitle}
              </span>
            </div>

            <div className="text-center space-y-2">
              <h1 className="text-2xl font-bold text-foreground">
                Welcome Back
              </h1>
              <p className="text-muted-foreground text-sm">
                Sign in to access your account
              </p>
            </div>

            <Button
              onClick={handleSSOLogin}
              size="lg"
              className="w-full bg-tvs-blue hover:bg-tvs-blue/90 text-primary-foreground font-semibold text-base py-6 rounded-xl transition-all duration-200 hover:shadow-lg hover:shadow-tvs-blue/20 hover:-translate-y-0.5"
            >
              <Shield className="mr-2.5 h-5 w-5" />
              Login with SSO
            </Button>

            <div className="w-full flex items-center gap-3">
              <div className="flex-1 h-px bg-border" />
              <span className="text-xs text-muted-foreground uppercase tracking-wider">
                Secure Access
              </span>
              <div className="flex-1 h-px bg-border" />
            </div>

            <p className="text-xs text-muted-foreground text-center leading-relaxed max-w-xs">
              You will be redirected to your organization's identity provider
              for authentication.
            </p>
          </div>
        </div>

        <p className="text-center text-xs text-muted-foreground mt-6">
          © {new Date().getFullYear()} TVS Credit Service Ltd. All rights reserved.
        </p>
      </div>
    </div>
  );
};

export default LoginPage;