// Eva Icons (c) 2018 Akveo, MIT; source SVG and license: src/assets/eva/.
type Props = { size?: number; className?: string; weight?: string };
export function Monitor({ size = 20, className = '' }: Props) {
  return (
    <svg
      aria-hidden="true"
      className={`eva-icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
    >
      <path d="M19,3H5A3,3,0,0,0,2,6v8a3,3,0,0,0,3,3h6v2H7a1,1,0,0,0,0,2H17a1,1,0,0,0,0-2H13V17h6a3,3,0,0,0,3-3V6A3,3,0,0,0,19,3Zm1,11a1,1,0,0,1-1,1H5a1,1,0,0,1-1-1V6A1,1,0,0,1,5,5H19a1,1,0,0,1,1,1Z" />
    </svg>
  );
}
export function Server({ size = 20, className = '' }: Props) {
  return (
    <svg
      aria-hidden="true"
      className={`eva-icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
    >
      <path d="M20.79,11.34,17.45,4.66A3,3,0,0,0,14.76,3H9.24A3,3,0,0,0,6.55,4.66L3.21,11.34a2,2,0,0,0-.21.9V18a3,3,0,0,0,3,3H18a3,3,0,0,0,3-3V12.24A2,2,0,0,0,20.79,11.34ZM8.34,5.55A1,1,0,0,1,9.24,5h5.52a1,1,0,0,1,.9.55L18.38,11H5.62ZM18,19H6a1,1,0,0,1-1-1V13H19v5A1,1,0,0,1,18,19Z" />
      <path d="M16,15H12a1,1,0,0,0,0,2h4a1,1,0,0,0,0-2Z" />
      <circle cx="8" cy="16" r="1" />
    </svg>
  );
}
export function Shield({ size = 20, className = '' }: Props) {
  return (
    <svg
      aria-hidden="true"
      className={`eva-icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
    >
      <path d="M12,21.85a2,2,0,0,1-1-.25l-.3-.17A15.17,15.17,0,0,1,3,8.23V8.09A2,2,0,0,1,4,6.34L11,2.4a2,2,0,0,1,2,0l7,3.94a2,2,0,0,1,1,1.75v.14a15.17,15.17,0,0,1-7.72,13.2l-.3.17A2,2,0,0,1,12,21.85Zm0-17.7L5,8.09v.14a13.15,13.15,0,0,0,6.7,11.45l.3.17.3-.17A13.15,13.15,0,0,0,19,8.23V8.09Z" />
    </svg>
  );
}
export function Grid({ size = 20, className = '' }: Props) {
  return (
    <svg
      aria-hidden="true"
      className={`eva-icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
    >
      <path d="M9,3H5A2,2,0,0,0,3,5V9a2,2,0,0,0,2,2H9a2,2,0,0,0,2-2V5A2,2,0,0,0,9,3ZM5,9V5H9V9Z" />
      <path d="M19,3H15a2,2,0,0,0-2,2V9a2,2,0,0,0,2,2h4a2,2,0,0,0,2-2V5A2,2,0,0,0,19,3ZM15,9V5h4V9Z" />
      <path d="M9,13H5a2,2,0,0,0-2,2v4a2,2,0,0,0,2,2H9a2,2,0,0,0,2-2V15A2,2,0,0,0,9,13ZM5,19V15H9v4Z" />
      <path d="M19,13H15a2,2,0,0,0-2,2v4a2,2,0,0,0,2,2h4a2,2,0,0,0,2-2V15A2,2,0,0,0,19,13Zm-4,6V15h4v4Z" />
    </svg>
  );
}
export function History({ size = 20, className = '' }: Props) {
  return (
    <svg
      aria-hidden="true"
      className={`eva-icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
    >
      <path d="M12,2A10,10,0,1,0,22,12,10,10,0,0,0,12,2Zm0,18a8,8,0,1,1,8-8A8,8,0,0,1,12,20Z" />
      <path d="M16,11H13V8a1,1,0,0,0-2,0v4a1,1,0,0,0,1,1h4a1,1,0,0,0,0-2Z" />
    </svg>
  );
}
export function Compare({ size = 20, className = '' }: Props) {
  return (
    <svg
      aria-hidden="true"
      className={`eva-icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
    >
      <path d="M12,8a1,1,0,0,0-1,1V20a1,1,0,0,0,2,0V9A1,1,0,0,0,12,8Z" />
      <path d="M19,4a1,1,0,0,0-1,1V20a1,1,0,0,0,2,0V5A1,1,0,0,0,19,4Z" />
      <path d="M5,12a1,1,0,0,0-1,1v7a1,1,0,0,0,2,0V13A1,1,0,0,0,5,12Z" />
    </svg>
  );
}
export function Settings({ size = 20, className = '' }: Props) {
  return (
    <svg
      aria-hidden="true"
      className={`eva-icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
    >
      <path d="M19,9a3,3,0,0,0-2.82,2H3a1,1,0,0,0,0,2H16.18A3,3,0,1,0,19,9Zm0,4a1,1,0,1,1,1-1A1,1,0,0,1,19,13Z" />
      <path d="M3,7H4.18A3,3,0,0,0,9.82,7H21a1,1,0,0,0,0-2H9.82A3,3,0,0,0,4.18,5H3A1,1,0,0,0,3,7ZM7,5A1,1,0,1,1,6,6,1,1,0,0,1,7,5Z" />
      <path d="M21,17H13.82a3,3,0,0,0-5.64,0H3a1,1,0,0,0,0,2H8.18a3,3,0,0,0,5.64,0H21a1,1,0,0,0,0-2ZM11,19a1,1,0,1,1,1-1A1,1,0,0,1,11,19Z" />
    </svg>
  );
}
export function Network({ size = 20, className = '' }: Props) {
  return (
    <svg
      aria-hidden="true"
      className={`eva-icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
    >
      <path d="M14.33,20h-.21a2,2,0,0,1-1.76-1.58L9.68,6,6.92,12.4A1,1,0,0,1,6,13H3a1,1,0,0,1,0-2H5.34L7.85,5.21a2,2,0,0,1,3.79.38L14.32,18l2.76-6.38A1,1,0,0,1,18,11h3a1,1,0,0,1,0,2H18.66l-2.51,5.79A2,2,0,0,1,14.33,20Z" />
    </svg>
  );
}
export function Plus({ size = 20, className = '' }: Props) {
  return (
    <svg
      aria-hidden="true"
      className={`eva-icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
    >
      <path d="M19,11H13V5a1,1,0,0,0-2,0v6H5a1,1,0,0,0,0,2h6v6a1,1,0,0,0,2,0V13h6a1,1,0,0,0,0-2Z" />
    </svg>
  );
}
export function Warning({ size = 20, className = '' }: Props) {
  return (
    <svg
      aria-hidden="true"
      className={`eva-icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
    >
      <path d="M22.56,16.3,14.89,3.58a3.43,3.43,0,0,0-5.78,0L1.44,16.3a3,3,0,0,0-.05,3A3.37,3.37,0,0,0,4.33,21H19.67a3.37,3.37,0,0,0,2.94-1.66A3,3,0,0,0,22.56,16.3Zm-1.7,2.05a1.31,1.31,0,0,1-1.19.65H4.33a1.31,1.31,0,0,1-1.19-.65,1,1,0,0,1,0-1L10.82,4.62a1.48,1.48,0,0,1,2.36,0l7.67,12.72A1,1,0,0,1,20.86,18.35Z" />
      <circle cx="12" cy="16" r="1" />
      <path d="M12,8a1,1,0,0,0-1,1v4a1,1,0,0,0,2,0V9A1,1,0,0,0,12,8Z" />
    </svg>
  );
}
