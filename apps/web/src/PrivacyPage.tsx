import { ArrowUpRight } from "lucide-react";
import { useEffect } from "react";
import { Link } from "react-router-dom";
import { MailentLogo } from "./components/MailentLogo";
import "./landing.css";

export function PrivacyPage() {
  useEffect(() => {
    document.title = "Privacy · Mailent";
    window.scrollTo(0, 0);
  }, []);
  return (
    <div className="paper-site privacy-site">
      <header className="paper-nav">
        <Link to="/" className="paper-logo" aria-label="Mailent home">
          <MailentLogo size={36} />
          mailent
        </Link>
        <Link to="/workspace" className="paper-button paper-button-small">
          Open workspace <ArrowUpRight size={18} />
        </Link>
      </header>
      <main className="privacy-content" id="main-content">
        <span className="paper-eyebrow">Privacy</span>
        <h1>Your data in Mailent.</h1>
        <p className="privacy-intro">
          What Mailent processes, where it is stored, and which services help
          provide the workspace.
        </p>
        <section>
          <h2>Captures and connection details</h2>
          <p>
            Uploaded network captures are processed on the Mailent server.
            Analysis includes connection addresses, protocols, encryption
            settings, certificates, and security findings. Captures can contain
            sensitive information; upload only data you are authorized to share.
          </p>
        </section>
        <section>
          <h2>Accounts and saved results</h2>
          <p>
            Supabase provides sign-in and database storage. Signed-in workspace
            records include capture results, reports, and account details. Guest
            results are temporary and are not saved to your account. Render
            hosts the application and processes requests.
          </p>
        </section>
        <section>
          <h2>Assisted analysis</h2>
          <p>
            When enabled, Jev, provided through Codiv, receives structured
            summaries of security findings and related connection metadata to
            help prioritize issues. Raw packet files, email bodies, and
            credentials are not included in these requests. Rules continue to
            check encryption and certificates if that service is unavailable.
          </p>
        </section>
        <section>
          <h2>Connected services</h2>
          <p>
            Domain checks contact DNS and the mail services being checked.
            Integrations send selected security events to destinations
            configured in the workspace. Enable only the connections your team
            needs.
          </p>
        </section>
        <section>
          <h2>Browser storage and data management</h2>
          <p>
            Mailent stores sign-in session information in your browser to keep
            you signed in. Guest mode is remembered for the current browser
            session. For access changes or removal of saved workspace records,
            contact the person who manages your Mailent deployment.
          </p>
        </section>
      </main>
      <footer className="paper-footer">
        <Link to="/">Mailent</Link>
        <Link to="/workspace">Back to workspace</Link>
      </footer>
    </div>
  );
}
