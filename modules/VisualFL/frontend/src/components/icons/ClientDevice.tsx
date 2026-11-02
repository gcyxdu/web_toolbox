export default function ClientDevice({
  malicious = false,
  size = 32,
}: {
  malicious?: boolean;
  size?: number;
}) {
  return (
    <svg
      className="client-device-icon"
      width={size}
      height={size}
      viewBox="0 0 40 36"
      fill="none"
      aria-hidden="true"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M23 10V4.5A2.5 2.5 0 0 1 25.5 2h10A2.5 2.5 0 0 1 38 4.5V31a2 2 0 0 1-2 2h-9" />
      <path d="M26.5 6h8v3h-8zM34 23v6M31 25v4" />
      <circle cx="32.5" cy="14" r="1.6" />
      <rect x="2" y="10.5" width="27" height="19" rx="2.5" fill="var(--device-screen, #fff)" />
      <path d="M2 25h27M12 29.5v3.5M19 29.5v3.5M9 34h13" />
      {malicious ? (
        <g stroke="none">
          <path
            d="M10.3 15.9 9 13.2l3.5 1.2a6 6 0 0 1 6 0l3.5-1.2-1.3 2.7a5.6 5.6 0 1 1-10.4 0Z"
            fill="#CC7C71"
          />
          <path d="m12 17 2 1m5-1-2 1m-3.5 2.4q2 1.8 4 0" stroke="#843F3B" strokeWidth="1" />
        </g>
      ) : (
        <path d="m6 15 3-2m-3 6 6-6" opacity=".5" />
      )}
    </svg>
  );
}
