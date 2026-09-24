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
    label: "Capture",
    icon: FileSearch,
    title: "Inspect real email traffic.",
    description:
      "Parse PCAP captures of SMTP, IMAP, and POP3 sessions with Zeek to verify STARTTLS, TLS versions, cipher suites, and X.509 chains.",
    chips: ["PCAP / PCAPNG", "STARTTLS & ciphers", "X.509 validation"],
    action: "Analyze a capture",
    href: "/workspace/overview?start=capture",
  },
  {
    label: "Domain",
    icon: Globe2,
    title: "Assess external mail posture.",
    description:
      "Discover mail exchangers and inspect MTA-STS, DANE, DNSSEC, SPF, DKIM, and live port encryption across all discovered hosts.",
    chips: ["MX Discovery", "MTA-STS & DANE", "DNSSEC & SPF"],
    action: "Check a domain",
    href: "/workspace/overview?start=domain",
  },
  {
    label: "Monitor",
    icon: Radar,
    title: "Continuous mail monitoring.",
    description:
      "Run persistent local collectors and scheduled checks to track configuration drift, certificate renewals, and protocol regressions.",
    chips: ["Live packet capture", "Drift detection", "Forensic dossiers"],
    action: "Explore monitoring",
    href: "/workspace/captures",
  },
];

export function LandingPage() {
  const [active, setActive] = useState(0);
  const approach = approaches[active];
  useEffect(() => {
    document.title = "Mailent — Clearer email security";
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
        <Link to="/workspace" className="home-button home-button-small">
          Open workspace <ArrowUpRight size={18} />
        </Link>
      </header>
      <main id="home-main">
        <section className="home-hero">
          <div className="hero-grid home-container">
            <div className="hero-copy">
              <div className="home-kicker">
                <span className="kicker-dot" /> Email traffic analysis with Zeek
              </div>
              <h1>
                Your mail traffic.
                <br />
                Its encryption.
                <br />
                <em>The evidence.</em>
              </h1>
              <p className="hero-description">
                Analyze SMTP, IMAP, and POP3 captures to find weak TLS, expired
                certificates, and failed encryption upgrades. Connect a collector
                to track your mail servers over time.
              </p>
              <div className="hero-actions">
                <Link
                  to="/workspace/overview?start=capture"
                  className="home-button"
                >
                  Analyze a capture <ArrowUpRight size={20} />
                </Link>
                <Link
                  to="/workspace/overview?start=domain"
                  className="home-button home-button-light"
                >
                  Check a domain <FileSearch size={19} />
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
                  <span className="window-label">The whole connection</span>
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
                    <span>mailent</span>
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
                  <Link to={approach.href}>
                    {approach.action}
                    <ArrowRight size={17} />
                  </Link>
                </div>
              </div>
              <div className="floating-note">
                <span>
                  <Layers3 size={20} />
                </span>
                <div>
                  From a single check
                  <br />
                  <strong>to the bigger picture.</strong>
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
                Captures, server checks, and monitoring
              </span>
              <h2>
                Analyze traffic.
                <br />
                <em>Track changes.</em>
              </h2>
            </div>
            <p>
              Inspect recorded connections with Zeek, check a server’s current
              configuration, and compare new results with previous checks.
            </p>
          </div>
          <div className="capability-grid">
            <Link
              to="/workspace/overview?start=domain"
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
              <h3>Check a mail domain</h3>
              <p>
                Find mail servers through DNS and check their TLS and certificates.
                Use a connected device for checks your cloud network cannot reach.
              </p>
              <span className="feature-link">
                Check a domain <ArrowRight size={18} />
              </span>
            </Link>
            <Link
              to="/workspace/overview?start=capture"
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
              <h3>Analyze a PCAP file</h3>
              <p>
                Reconstruct mail sessions with Zeek. Review STARTTLS, TLS versions,
                cipher suites, Forward Secrecy, and captured certificates.
              </p>
              <span className="feature-link">
                Analyze a capture <ArrowRight size={18} />
              </span>
            </Link>
            <Link
              to="/workspace/captures"
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
                  <span>Check. Compare. Repeat.</span>
                </div>
              </div>
              <h3>Monitor your mail servers</h3>
              <p>
                Collect live traffic with Zeek and schedule server checks. Track
                certificate changes, weaker encryption, and new findings.
              </p>
              <span className="feature-link">
                Explore monitoring <ArrowRight size={18} />
              </span>
            </Link>
          </div>
        </section>

        <section className="workflow-section" id="workflow">
          <div className="home-container workflow-grid">
            <div className="workflow-copy" data-reveal>
              <span className="home-kicker">From evidence to a verified fix</span>
              <h2>
                A finding is
                <br />
                just the <em>start.</em>
              </h2>
              <p>
                Trace each finding to a connection or certificate. Review the
                suggested fix, then run another check to verify the change.
              </p>
              <Link className="home-button" to="/workspace">
                Open workspace <ArrowUpRight size={19} />
              </Link>
            </div>
            <div className="workflow-steps">
              {[
                [
                  "01",
                  "See what needs attention",
                  "Findings are linked to the connections, certificates, and settings that produced them.",
                  FileSearch,
                ],
                [
                  "02",
                  "Prioritize and fix issues",
                  "Use severity and AI-assisted risk review to prioritize findings. Verify fixes with a new capture or server check.",
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
              <span>Connected devices</span>
            </div>
            <div className="network-node node-four">
              <FileText size={24} />
              <span>Shared reports</span>
            </div>
          </div>
          <div className="network-copy" data-reveal>
            <span className="home-kicker">Local collection, shared results</span>
            <h2>
              Close to your mail.
              <br />
              <em>Wherever it runs.</em>
            </h2>
            <p>
              Run the CLI on your network for server checks and Zeek traffic
              collection. Send results to your workspace to review connections,
              findings, and changes in one place.
            </p>
            <ul>
              <li>
                <Check size={18} />
                Domain checks and uploaded captures
              </li>
              <li>
                <Check size={18} />
                Scheduled checks from cloud or connected devices
              </li>
              <li>
                <Check size={18} />
                Webhooks, syslog, and downloadable reports
              </li>
            </ul>
            <Link className="home-text-link" to="/workspace/devices">
              Connect your workspace <ChevronRight size={20} />
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
                One command.
                <br />
                <em>Your own network.</em>
              </h2>
            </div>
            <p>
              Check domains, analyze captures, and run scheduled checks from
              your machine. Connect the CLI to keep your results in the
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
            <span>Then connect your device</span>
            <code>mailent login --server https://mailent.onrender.com</code>
          </div>
          <p className="install-note">
            Installs Mailent CLI and verifies required Zeek 8+. Uses your native Zeek or sets up the container runner with Docker or Podman.
          </p>
        </section>

        <section className="home-final home-container" data-reveal>
          <div>
            <MailentLogo size={62} />
            <span className="home-kicker">Verify your email security</span>
          </div>
          <h2>
            Passive PCAP forensic inspection
            <br />
            <em>with Zeek 8+.</em>
          </h2>
          <Link to="/workspace/overview?start=capture" className="home-button">
            Analyze a capture <ArrowUpRight size={21} />
          </Link>
          <p>
            Or{" "}
            <Link to="/workspace/overview?start=domain">
              check an external mail domain.
            </Link>
          </p>
        </section>
      </main>
      <footer className="home-footer home-container">
        <Link to="/" className="home-brand">
          <MailentLogo size={34} />
          mailent
        </Link>
        <span>Email traffic analysis with Zeek.</span>
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
