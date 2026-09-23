import {
  ArrowDown,
  ArrowUpRight,
  Check,
  FileSearch,
  Fingerprint,
  LockKeyhole,
  Mail,
  MoveRight,
  ShieldCheck,
} from "lucide-react";
import { useEffect } from "react";
import { Link } from "react-router-dom";
import "@fontsource-variable/source-serif-4";
import "./landing.css";
import { MailentLogo } from "./components/MailentLogo";

export function LandingPage() {
  useEffect(() => {
    document.title = "Mailent — Email security, in plain sight";
  }, []);
  return (
    <div className="paper-site">
      <a href="#product" className="skip-link">
        Skip to content
      </a>
      <header className="paper-nav">
        <Link to="/" className="paper-logo" aria-label="Mailent home">
          <MailentLogo size={32} />
          mailent<span>®</span>
        </Link>
        <nav aria-label="Website">
          <a href="#product">Product</a>
          <a href="#workflow">How it works</a>
          <a href="#evidence">The evidence</a>
        </nav>
        <Link to="/workspace" className="paper-button paper-button-small">
          Open workspace <ArrowUpRight size={18} />
        </Link>
      </header>
      <main>
        <section className="paper-hero" id="product">
          <div className="paper-eyebrow">
            <span /> A closer look at mail transport
          </div>
          <h1>
            Email security,
            <br />
            <em>in plain sight.</em>
          </h1>
          <p className="paper-intro">
            See how your mail is protected, where it falls short,
            <br className="desktop-break" /> and what to fix — with the evidence
            to back it up.
          </p>
          <div className="paper-actions">
            <Link className="paper-button" to="/workspace">
              Open your workspace <ArrowUpRight size={20} />
            </Link>
            <a href="#workflow" className="paper-button paper-button-outline">
              Explore the workflow <ArrowDown size={18} />
            </a>
          </div>
          <div className="paper-protocols">
            <span>Built for mail traffic</span>
            <i /> SMTP <i /> IMAP <i /> POP3
          </div>
          <div
            className="paper-artifact paper-artifact-left"
            aria-hidden="true"
          >
            <span className="artifact-label">
              <FileSearch size={18} /> Capture evidence
            </span>
            <div className="packet-lines">
              <i />
              <i />
              <i />
              <i />
              <i />
              <i />
              <i />
              <i />
            </div>
            <div className="artifact-bottom">
              Every finding has a source.
              <Fingerprint size={22} />
            </div>
          </div>
          <div
            className="paper-artifact paper-artifact-right"
            aria-hidden="true"
          >
            <span className="artifact-label">
              <LockKeyhole size={18} /> Transport security
            </span>
            <div className="protocol-stack">
              <span>
                Protocol negotiation
                <MoveRight size={16} />
              </span>
              <span>
                TLS & encryption
                <MoveRight size={16} />
              </span>
              <span>
                Certificate chain
                <MoveRight size={16} />
              </span>
            </div>
          </div>
        </section>
        <section
          className="paper-evidence"
          id="evidence"
          aria-labelledby="evidence-title"
        >
          <div className="paper-section-top">
            <span className="paper-eyebrow">01 / See the whole connection</span>
            <span>From the network. For your review.</span>
          </div>
          <div className="paper-evidence-grid">
            <div>
              <h2 id="evidence-title">
                Less guesswork.
                <br />
                <em>More evidence.</em>
              </h2>
              <p>
                Bring a network capture. Mailent reconstructs the email
                connections and checks their encryption, certificates, and
                protocol behavior.
              </p>
              <a href="#workflow" className="paper-text-link">
                Follow a capture through <MoveRight size={21} />
              </a>
            </div>
            <div className="connection-sheet">
              <div className="sheet-heading">
                <span>
                  <span className="sheet-dot" /> The connection record
                </span>
                <Fingerprint size={22} />
              </div>
              <div className="connection-path">
                <span>
                  <Mail size={26} /> Mail client
                </span>
                <div>
                  <i />
                  <LockKeyhole size={23} />
                  <i />
                </div>
                <span>
                  <ShieldCheck size={26} /> Mail server
                </span>
              </div>
              <div className="sheet-row">
                <span>What was negotiated?</span>
                <strong>Protocol & TLS</strong>
              </div>
              <div className="sheet-row">
                <span>What was presented?</span>
                <strong>Certificate evidence</strong>
              </div>
              <div className="sheet-row">
                <span>What needs attention?</span>
                <strong>Findings & next steps</strong>
              </div>
              <div className="sheet-note">
                Evidence gaps stay visible. Missing data is never treated as a
                pass.
              </div>
            </div>
          </div>
        </section>
        <section
          className="paper-workflow"
          id="workflow"
          aria-labelledby="workflow-title"
        >
          <div className="paper-workflow-title">
            <span className="paper-eyebrow">02 / A practical workflow</span>
            <h2 id="workflow-title">
              From captured traffic
              <br />
              to a <em>verified next step.</em>
            </h2>
          </div>
          <div className="paper-steps">
            {[
              [
                "01",
                "Bring your data",
                "Upload a PCAP or connect a collector to monitor traffic from your network.",
              ],
              [
                "02",
                "Review what matters",
                "Inspect findings alongside the sessions, certificates, and policy checks that produced them.",
              ],
              [
                "03",
                "Fix. Verify. Keep a record.",
                "Track remediation, run authorized verification checks, and export the evidence.",
              ],
            ].map(([number, title, body]) => (
              <article key={number}>
                <span className="step-number">{number}</span>
                <h3>{title}</h3>
                <p>{body}</p>
              </article>
            ))}
          </div>
        </section>
        <section className="paper-close">
          <div>
            <span className="paper-eyebrow">Your network. Your evidence.</span>
            <h2>Take a closer look.</h2>
          </div>
          <Link to="/workspace" className="paper-button">
            Open workspace <ArrowUpRight size={20} />
          </Link>
        </section>
      </main>
      <footer className="paper-footer">
        <Link to="/" className="paper-logo">
          <MailentLogo size={28} />
          mailent
        </Link>
        <span>Email transport security, with a record you can inspect.</span>
        <span className="paper-footer-note">
          <Check size={17} /> Private workspace
        </span>
      </footer>
    </div>
  );
}
