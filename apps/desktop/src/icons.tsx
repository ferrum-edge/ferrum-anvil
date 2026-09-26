// Inline SVG icon set: one 24×24 stroke grid, drawn in currentColor so icons
// follow the text colour of their button. Decorative only (aria-hidden); the
// control that holds an icon carries the accessible name.
import type { ReactNode } from "react";

const GEAR =
  "M10.02 4.87 L10.42 2.53 L13.58 2.53 L13.98 4.87 L15.64 5.56 L17.57 4.18 L19.82 6.43 L18.44 8.36 L19.13 10.02 L21.47 10.42 L21.47 13.58 L19.13 13.98 L18.44 15.64 L19.82 17.57 L17.57 19.82 L15.64 18.44 L13.98 19.13 L13.58 21.47 L10.42 21.47 L10.02 19.13 L8.36 18.44 L6.43 19.82 L4.18 17.57 L5.56 15.64 L4.87 13.98 L2.53 13.58 L2.53 10.42 L4.87 10.02 L5.56 8.36 L4.18 6.43 L6.43 4.18 L8.36 5.56Z";

const PATHS = {
  plus: <path d="M12 5v14M5 12h14" />,
  x: <path d="M6 6l12 12M18 6 6 18" />,
  check: <path d="m5 12.5 4.5 4.5L19 7" />,
  chevronDown: <path d="m6 9 6 6 6-6" />,
  chevronRight: <path d="m9 6 6 6-6 6" />,
  chevronLeft: <path d="m15 6-6 6 6 6" />,
  arrowUp: <path d="M12 19V5M6 11l6-6 6 6" />,
  arrowDown: <path d="M12 5v14M6 13l6 6 6-6" />,
  gear: (
    <>
      <path d={GEAR} />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  sliders: <path d="M4 7h9M17 7h3M4 17h3M11 17h9M15 5v4M9 15v4" />,
  lock: (
    <>
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" />
    </>
  ),
  key: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="m10.8 12.2 9.2-9.2M16 7l3 3M14 9l2 2" />
    </>
  ),
  folder: <path d="M3 7.5A2.5 2.5 0 0 1 5.5 5H9l2 2.2h7.5A2.5 2.5 0 0 1 21 9.7v7.8a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z" />,
  folderOpen: <path d="M3 17.5v-10A2.5 2.5 0 0 1 5.5 5H9l2 2.2h6A2.5 2.5 0 0 1 19.5 9.7V11M3 17.5 5.3 12.3A2 2 0 0 1 7.1 11H20a1 1 0 0 1 .95 1.3l-1.9 5.9A2.5 2.5 0 0 1 16.7 20H5.5A2.5 2.5 0 0 1 3 17.5z" />,
  folderPlus: (
    <>
      <path d="M3 7.5A2.5 2.5 0 0 1 5.5 5H9l2 2.2h7.5A2.5 2.5 0 0 1 21 9.7v7.8a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z" />
      <path d="M12 10.5v6M9 13.5h6" />
    </>
  ),
  file: (
    <>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
      <path d="M14 3v5h5" />
    </>
  ),
  trash: <path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" />,
  pencil: <path d="M4 20h4L19 9a2.83 2.83 0 0 0-4-4L4 16zM13.5 6.5l4 4" />,
  copy: (
    <>
      <rect x="8" y="8" width="12" height="12" rx="2" />
      <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" />
    </>
  ),
  eye: (
    <>
      <path d="M2.5 12S6 5 12 5s9.5 7 9.5 7-3.5 7-9.5 7-9.5-7-9.5-7z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  eyeOff: <path d="M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6 0 9.5 7 9.5 7a17 17 0 0 1-2.6 3.5M6.6 6.6C4 8.3 2.5 12 2.5 12S6 19 12 19a9.5 9.5 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2" />,
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-4-4" />
    </>
  ),
  history: <path d="M3.5 12a8.5 8.5 0 1 0 2.5-6M3.5 4v4.5H8M12 8v4.5l3 2" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  layers: <path d="m12 3 9 5-9 5-9-5zM3 12.5l9 5 9-5M3 17l9 5 9-5" />,
  send: <path d="M21 3 10 14M21 3l-6.5 18-4.5-7-7-4.5z" />,
  play: <path d="M7 4.5v15l12.5-7.5z" />,
  stop: <rect x="6" y="6" width="12" height="12" rx="2" />,
  zap: <path d="M13 2 4.5 13.5H11L10 22l8.5-11.5H12z" />,
  listChecks: <path d="M11 6h9M11 12h9M11 18h9M3.5 6l1.5 1.5L8 4.5M3.5 12l1.5 1.5L8 10.5M3.5 18l1.5 1.5L8 16.5" />,
  download: <path d="M12 3v12M7 10l5 5 5-5M4 15v3.5A2.5 2.5 0 0 0 6.5 21h11a2.5 2.5 0 0 0 2.5-2.5V15" />,
  upload: <path d="M12 15V3M7 8l5-5 5 5M4 15v3.5A2.5 2.5 0 0 0 6.5 21h11a2.5 2.5 0 0 0 2.5-2.5V15" />,
  shield: <path d="M12 3 5 6v5.5c0 4.5 3 8 7 9.5 4-1.5 7-5 7-9.5V6zM9 12l2 2 4-4.5" />,
  globe: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a13.5 13.5 0 0 1 0 18M12 3a13.5 13.5 0 0 0 0 18" />
    </>
  ),
  sidebar: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2.5" />
      <path d="M9.5 4v16" />
    </>
  ),
  splitRows: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2.5" />
      <path d="M3 12h18" />
    </>
  ),
  splitColumns: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2.5" />
      <path d="M12 4v16" />
    </>
  ),
  plug: <path d="M9 3v5M15 3v5M6.5 8h11v3a5.5 5.5 0 0 1-11 0zM12 16.5V21" />,
  alertTriangle: <path d="M10.3 4.1 2.6 17.5A2 2 0 0 0 4.3 20.5h15.4a2 2 0 0 0 1.7-3L13.7 4.1a2 2 0 0 0-3.4 0zM12 9.5v4M12 17h.01" />,
  alertCircle: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7.5v5.5M12 16.5h.01" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5.5M12 7.5h.01" />
    </>
  ),
  checkCircle: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="m8.5 12.3 2.4 2.4 4.8-5" />
    </>
  ),
  xCircle: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="m9 9 6 6M15 9l-6 6" />
    </>
  ),
  activity: <path d="M3 12h4l2.5-7 5 14 2.5-7h4" />,
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;

export function Icon(props: { name: IconName; size?: number; className?: string; strokeWidth?: number }) {
  const size = props.size ?? 16;
  const filled = props.name === "play";
  return (
    <svg
      className={`icon${props.className ? ` ${props.className}` : ""}`}
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill={filled ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth={props.strokeWidth ?? 1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[props.name]}
    </svg>
  );
}
