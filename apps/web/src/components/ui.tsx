import { type ButtonHTMLAttributes, forwardRef, type ReactNode } from "react";
import { Icon } from "./Icon";

export const Button = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement> & {
    variant?: "primary" | "secondary" | "danger";
  }
>(function Button(
  { variant = "secondary", className = "", type = "button", ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={`btn btn-${variant} ${className}`}
      {...props}
    />
  );
});
export function PageHeader({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  children?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {children}
    </div>
  );
}
export function EmptyState({
  icon = "folder_open",
  title,
  description,
  children,
}: {
  icon?: string;
  title: string;
  description: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon">
        <Icon name={icon} size={25} />
      </span>
      <h3>{title}</h3>
      <p>{description}</p>
      {children}
    </div>
  );
}
export function ErrorState({
  title = "Unable to load data",
  description,
  onRetry,
}: {
  title?: string;
  description: string;
  onRetry?: () => void;
}) {
  return (
    <div className="error-state" role="alert">
      <Icon name="error" />
      <div>
        <strong>{title}</strong>
        <p>{description}</p>
      </div>
      {onRetry && <Button onClick={onRetry}>Try again</Button>}
    </div>
  );
}
export function LoadingState({ label = "Loading data…" }: { label?: string }) {
  return (
    <div className="loading-state" role="status">
      <Icon name="refresh" className="spin" />
      <span>{label}</span>
    </div>
  );
}
export function SearchField({
  value,
  onChange,
  placeholder,
  label,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  label: string;
}) {
  return (
    <div className="search-field">
      <Icon name="search" size={17} />
      <input
        type="search"
        aria-label={label}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}
