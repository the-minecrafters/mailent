import { type CSSProperties, useId } from "react";

export interface MailentLogoProps {
  size?: number | string;
  className?: string;
  style?: CSSProperties;
  "aria-label"?: string;
}

export function MailentLogo({
  size = 32,
  className,
  style,
  "aria-label": ariaLabel = "Mailent logo",
}: MailentLogoProps) {
  const rawId = useId();
  const clipId = `mailent-envelope-body-${rawId.replace(/[^a-zA-Z0-9_-]/g, "")}`;

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 256 256"
      width={size}
      height={size}
      role="img"
      aria-label={ariaLabel}
      className={className}
      style={{
        display: "inline-block",
        flexShrink: 0,
        verticalAlign: "middle",
        ...style,
      }}
    >
      <defs>
        <clipPath id={clipId}>
          <rect x="20" y="52" width="216" height="152" rx="40" />
        </clipPath>
      </defs>
      {/* soft rounded envelope */}
      <rect x="20" y="52" width="216" height="152" rx="40" fill="#6366F1" />
      {/* flap shaped like a smile */}
      <path
        clipPath={`url(#${clipId})`}
        fill="#A5B4FC"
        d="M-10 0 H266 V88 Q128 212 -10 88 Z"
      />
      {/* eyes */}
      <circle cx="94" cy="104" r="9" fill="#312E81" />
      <circle cx="162" cy="104" r="9" fill="#312E81" />
      {/* friendly check badge */}
      <circle
        cx="200"
        cy="190"
        r="34"
        fill="#34D399"
        stroke="#6366F1"
        strokeWidth="8"
      />
      <path
        d="M184 190 l11 11 l21 -23"
        fill="none"
        stroke="#fff"
        strokeWidth="9"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default MailentLogo;
