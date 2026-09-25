import {
  ArrowDown,
  ArrowRight,
  ArrowUpRight,
  CalendarClock,
  Check,
  ChevronRight,
  FileSearch,
  FileText,
  Globe2,
  Layers3,
  LockKeyhole,
  Network,
  Radar,
  RefreshCw,
  Server,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { CLI_RELEASE_URL, InstallCommand } from "./components/InstallCommand";
import "@fontsource-variable/source-serif-4";
import "./home.css";
import { MailentLogo } from "./components/MailentLogo";

const approaches = [
  {
    label: "Analyze",
    icon: FileSearch,
    title: "Analyze captures on your machine.",
    description:
      "Run mailent analyze to reconstruct SMTP, IMAP, and POP3 sessions with Zeek. Review TLS, STARTTLS, ciphers, and captured certificates; sync the results when you need a shared view.",
    chips: ["PCAP / PCAPNG", "STARTTLS & ciphers", "Captured certificates"],
    action: "Install Mailent CLI",
    href: "#install",
  },
  {
    label: "Scan",
    icon: Globe2,
    title: "Scan mail infrastructure from your network.",
    description:
      "Run mailent scan to discover mail servers, check DNS policies, and test their TLS and certificates. Connections originate from your machine.",
    chips: ["MX Discovery", "MTA-STS & DANE", "DNSSEC & SPF"],
    action: "Install Mailent CLI",
    href: "#install",
  },
  {
    label: "Monitor",
    icon: Radar,
    title: "Monitor live traffic with Zeek.",
    description:
      "Run mailent monitor on a local network interface to continuously observe mail connections. Sync the evidence to review new findings and changes over time.",
    chips: ["Live traffic", "Local Zeek analysis", "Synced evidence"],
    action: "Install Mailent CLI",
    href: "#install",
  },
];

export function LandingPage() {
  const [active, setActive] = useState(0);
  const approach = approaches[active];
  useEffect(() => {
    document.title = "Mailent — Local mail analysis. Shared analyst workspace.";
    if (!window.location.hash) window.scrollTo(0, 0);
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const elements = document.querySelectorAll(".marketing-site [data-reveal]");
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries)
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
      },
      { threshold: 0.12 },
    );
    for (const element of elements) {
      element.classList.add("will-reveal");
      observer.observe(element);
    }
    return () => observer.disconnect();
  }, []);
  return (
    <div className="marketing-site">
      <a className="skip-link" href="#home-main">
        Skip to content
      </a>
      <header className="home-nav home-container">
        <Link to="/" className="home-brand" aria-label="Mailent home">
          <MailentLogo size={42} />
          mailent
        </Link>
        <nav aria-label="Website">
          <a href="#possibilities">Product</a>
          <a href="#workflow">How it works</a>
          <a href="#install">CLI</a>
          <Link to="/privacy">Privacy</Link>
        </nav>
        <a href="#install" className="home-button home-button-small">
          Install CLI <ArrowUpRight size={18} />
        </a>
      </header>
      <main id="home-main">
        <section className="home-hero">
          <div className="hero-grid home-container">
            <div className="hero-copy">
              <div className="home-kicker">
                <span className="kicker-dot" /> Mailent CLI + Analyst Workspace
              </div>
              <h1>
                Analyze locally.
                <br />
                Review together.
                <br />
                <em>See what changed.</em>
              </h1>
              <p className="hero-description">
                Analyze captures, scan mail infrastructure, and monitor live
                traffic with Mailent CLI. Sync structured results to your workspace
                for AI-assisted review, investigations, and reports.
              </p>
              <div className="hero-actions">
                <a href="#install" className="home-button">
                  Install Mailent CLI <ArrowUpRight size={20} />
                </a>
                <Link
                  to="/workspace"
                  className="home-button home-button-light"
                >
                  Open workspace <FileSearch size={19} />
                </Link>
              </div>
              <a className="hero-explore" href="#possibilities">
                <span>
                  <ArrowDown size={17} />
                </span>
                See what Mailent checks
              </a>
            </div>
            <div className="hero-visual">
              <div className="hero-orbit orbit-one" aria-hidden="true" />
              <div className="hero-orbit orbit-two" aria-hidden="true" />
              <span className="floating-spark spark-one" aria-hidden="true">
                ✦
              </span>
              <span className="floating-spark spark-two" aria-hidden="true">
                ✦
              </span>
              <div className="product-window">
                <div className="product-window-bar">
                  <span className="window-mark">
                    <MailentLogo size={28} />
                    mailent
                  </span>
                  <span className="window-label">Analysis starts in your terminal</span>
                  <span className="window-dots" aria-hidden="true">
                    <i />
                    <i />
                    <i />
                  </span>
                </div>
                <div
                  className="product-switcher"
                  role="group"
                  aria-label="Explore Mailent"
                >
                  {approaches.map((item, index) => {
                    const ItemIcon = item.icon;
                    return (
                      <button
                        key={item.label}
                        onClick={() => setActive(index)}
                        aria-pressed={active === index}
                      >
                        <ItemIcon size={17} />
                        {item.label}
                      </button>
                    );
                  })}
                </div>
                <div className="connection-visual" aria-hidden="true">
                  <svg
                    className="connection-wires"
                    viewBox="0 0 520 210"
                    fill="none"
                  >
                    <path d="M120 105 H245 Q265 105 265 85 V44 Q265 28 288 28 H373 M120 105 H373 M120 105 H245 Q265 105 265 125 V169 Q265 185 285 185 H373" />
                    <path
                      className="wire-pulse"
                      d="M120 105 H245 Q265 105 265 85 V44 Q265 28 288 28 H373 M120 105 H373 M120 105 H245 Q265 105 265 125 V169 Q265 185 285 185 H373"
                    />
                  </svg>
                  <div className="connection-source">
                    <MailentLogo size={96} />
                    <span>Mailent CLI</span>
                  </div>
                  <div className="connection-destinations" key={active}>
                    {approach.chips.map((chip, index) => (
                      <span key={chip}>
                        <i>
                          {index === 0 ? (
                            <Network size={18} />
                          ) : index === 1 ? (
                            <LockKeyhole size={18} />
                          ) : (
                            <ShieldCheck size={18} />
                          )}
                        </i>
                        {chip}
                      </span>
                    ))}
                  </div>
                </div>
                <div
                  className="product-caption"
                  aria-live="polite"
                  aria-atomic="true"
                  key={`caption-${active}`}
                >
                  <h2>{approach.title}</h2>
                  <p>{approach.description}</p>
                  <a href={approach.href}>
                    {approach.action}
                    <ArrowRight size={17} />
                  </a>
                </div>
              </div>
              <div className="floating-note">
                <span>
                  <Layers3 size={20} />
                </span>
                <div>
                  Local analysis.
                  <br />
                  <strong>Shared evidence.</strong>
                </div>
              </div>
            </div>
          </div>
          <div className="protocol-strip home-container">
            <span>Mail protocols and transport encryption</span>
            <div>
              <span>SMTP</span>
              <i />
              <span>IMAP</span>
              <i />
              <span>POP3</span>
              <i />
              <span>TLS</span>
            </div>
          </div>
        </section>

        <section
          className="possibilities home-container home-section"
          id="possibilities"
        >
          <div className="section-heading" data-reveal>
            <div>
              <span className="home-kicker">
                Three workflows. One CLI.
              </span>
              <h2>
                Run it locally.
                <br />
                <em>Keep the evidence.</em>
              </h2>
            </div>
            <p>
              Your machine handles packet analysis and network connections.
              Choose a capture, a domain, or a live interface to get started.
            </p>
          </div>
          <div className="capability-grid">
            <a
              href="#install"
              className="capability-card capability-capture"
              data-reveal
            >
              <span className="feature-topline">
                <FileSearch size={24} />
                <ArrowUpRight size={23} />
              </span>
              <div className="capture-art" aria-hidden="true">
                <span className="file-pill">.pcap</span>
                <div className="capture-wave">
                  {[28, 48, 35, 74, 92, 58, 82, 44, 65, 32, 50, 26].map(
                    (height, index) => (
                      <i
                        key={index}
                        style={{
                          height: `${height}%`,
                          animationDelay: `${index * -0.16}s`,
                        }}
                      />
                    ),
                  )}
                </div>
              </div>
              <h3>Analyze captures</h3>
              <p>
                Investigate captured SMTP, IMAP, and POP3 traffic with Zeek.
                Inspect STARTTLS, TLS versions, ciphers, and certificates locally.
              </p>
              <span className="feature-link">
                mailent analyze <ArrowRight size={18} />
              </span>
            </a>
            <a
              href="#install"
              className="capability-card capability-domain"
              data-reveal
            >
              <span className="feature-topline">
                <Globe2 size={24} />
                <ArrowUpRight size={23} />
              </span>
              <div className="domain-art" aria-hidden="true">
                <span>
                  <Globe2 size={32} />
                </span>
                <i />
                <div>
                  <span>DNS</span>
                  <span>TLS</span>
                  <span>Certificates</span>
                </div>
              </div>
              <h3>Scan mail infrastructure</h3>
              <p>
                Discover mail servers through DNS, then actively check their
                policies, TLS, and certificates from your network.
              </p>
              <span className="feature-link">
                mailent scan <ArrowRight size={18} />
              </span>
            </a>
            <a
              href="#install"
              className="capability-card capability-monitor"
              data-reveal
            >
              <span className="feature-topline">
                <CalendarClock size={24} />
                <ArrowUpRight size={23} />
              </span>
              <div className="monitor-art" aria-hidden="true">
                <div className="monitor-track">
                  <span />
                  <span />
                  <span />
                  <span />
                  <span />
                </div>
                <div className="monitor-event">
                  <RefreshCw size={19} />
                  <span>Observe. Sync. Compare.</span>
                </div>
              </div>
              <h3>Monitor live traffic</h3>
              <p>
                Continuously observe mail traffic on a local network interface.
                Send new evidence to the workspace as connections arrive.
              </p>
              <span className="feature-link">
                mailent monitor <ArrowRight size={18} />
              </span>
            </a>
          </div>
        </section>

        <section className="workflow-section" id="workflow">
          <div className="home-container workflow-grid">
            <div className="workflow-copy" data-reveal>
              <span className="home-kicker">Mailent Workspace</span>
              <h2>
                Your analysis,
                <br />
                <em>in context.</em>
              </h2>
              <p>
                Sync results from the CLI into a shared analyst view. Compare
                assessments, investigate findings, track fixes, and report on
                the evidence behind each decision.
              </p>
              <Link className="home-button" to="/workspace">
                Open workspace <ArrowUpRight size={19} />
              </Link>
            </div>
            <div className="workflow-steps">
              {[
                [
                  "01",
                  "Review history and drift",
                  "Compare assessments over time. See which certificates, encryption settings, and findings have changed.",
                  FileSearch,
                ],
                [
                  "02",
                  "Investigate and track fixes",
                  "Use AI-assisted analysis to prioritize findings, correlate evidence, and track remediation. Sync another CLI assessment to verify a change.",
                  ShieldCheck,
                ],
                [
                  "03",
                  "Export the evidence",
                  "Download JSON, HTML, or PDF reports with findings, connection details, and the limits of the captured evidence.",
                  FileText,
                ],
              ].map(([number, title, body, StepIcon]) => {
                const Icon = StepIcon as typeof FileSearch;
                return (
                  <article
                    data-reveal
                    className="workflow-step-card"
                    key={String(number)}
                  >
                    <span className="step-index">{String(number)}</span>
                    <div>
                      <h3>{String(title)}</h3>
                      <p>{String(body)}</p>
                    </div>
                    <Icon size={23} />
                  </article>
                );
              })}
            </div>
          </div>
        </section>

        <section className="network-section home-container home-section">
          <div className="network-art" data-reveal aria-hidden="true">
            <div className="network-ring" />
            <div className="network-center">
              <MailentLogo size={92} />
            </div>
            <div className="network-node node-one">
              <Server size={24} />
              <span>Mail servers</span>
            </div>
            <div className="network-node node-two">
              <Network size={24} />
              <span>Your network</span>
            </div>
            <div className="network-node node-three">
              <Radar size={24} />
              <span>Mailent CLI</span>
            </div>
            <div className="network-node node-four">
              <FileText size={24} />
              <span>Shared reports</span>
            </div>
          </div>
          <div className="network-copy" data-reveal>
            <span className="home-kicker">Local collection, shared results</span>
            <h2>
              CLI for analysis.
              <br />
              <em>Workspace for answers.</em>
            </h2>
            <p>
              PCAP processing and live network work stay on your machine.
              The workspace receives structured assessments and evidence so
              analysts can review the results together.
            </p>
            <ul>
              <li>
                <Check size={18} />
                Local captures, active scans, and live monitoring
              </li>
              <li>
                <Check size={18} />
                Assessment history, drift, and investigations
              </li>
              <li>
                <Check size={18} />
                AI-assisted review, remediation, and reports
              </li>
            </ul>
            <Link className="home-text-link" to="/workspace/installations">
              Connect a Mailent installation <ChevronRight size={20} />
            </Link>
          </div>
        </section>

        <section
          id="install"
          className="home-install home-container"
          data-reveal
        >
          <div className="install-heading">
            <div>
              <span className="home-kicker">Mailent, from your terminal</span>
              <h2>
                Install the CLI.
                <br />
                <em>Connect your workspace.</em>
              </h2>
            </div>
            <p>
              Install Mailent and sign in to connect this installation. Run
              analysis locally, then sync results whenever you need the shared
              workspace.
            </p>
          </div>
          <InstallCommand />
          <div className="install-details">
            <span>Linux x86_64 & Windows x64</span>
            <a href={CLI_RELEASE_URL}>
              GitHub release <ArrowUpRight size={17} />
            </a>
            <a href="/install.sh" download>
              Linux script <ArrowDown size={16} />
            </a>
            <a href="/install.ps1" download>
              PowerShell script <ArrowDown size={16} />
            </a>
          </div>
          <div className="install-next">
            <span>Connect your installation</span>
            <code>mailent login --server https://mailent.onrender.com</code>
          </div>
          <div className="install-next">
            <span>Analyze a capture and sync</span>
            <code>mailent analyze &lt;capture.pcap&gt; --sync</code>
          </div>
          <div className="install-next">
            <span>Scan mail infrastructure and sync</span>
            <code>mailent scan &lt;domain&gt; --sync</code>
          </div>
          <div className="install-next">
            <span>Monitor live traffic</span>
            <code>mailent monitor --interface &lt;iface&gt;</code>
          </div>
          <p className="install-note">
            Installs Mailent CLI and verifies required Zeek 8+. Uses your native Zeek or sets up the container runner with Docker or Podman.
          </p>
        </section>

        <section className="home-final home-container" data-reveal>
          <div>
            <MailentLogo size={62} />
            <span className="home-kicker">Start with Mailent CLI</span>
          </div>
          <h2>
            Analyze. Scan. Monitor.
            <br />
            <em>Review it all together.</em>
          </h2>
          <a href="#install" className="home-button">
            Install Mailent CLI <ArrowUpRight size={21} />
          </a>
          <p>
            Or{" "}
            <Link to="/workspace">open your analyst workspace.</Link>
          </p>
        </section>
      </main>
      <footer className="home-footer home-container">
        <Link to="/" className="home-brand">
          <MailentLogo size={34} />
          mailent
        </Link>
        <span>Local mail analysis. Shared evidence.</span>
        <nav aria-label="Footer">
          <Link to="/privacy">Privacy</Link>
          <Link to="/workspace">
            Workspace <ArrowUpRight size={16} />
          </Link>
        </nav>
      </footer>
    </div>
  );
}
