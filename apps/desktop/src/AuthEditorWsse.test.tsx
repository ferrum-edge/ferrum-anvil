import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { AuthConfig, WsseConfig } from "./generated/contracts";

vi.mock("./api", () => ({
  api: {},
  onOAuthFlow: vi.fn(async () => () => {}),
}));
// Secret fields render their label only: the editor never shows a value.
vi.mock("./ui", () => ({
  SecretField: (props: { label: string }) => <span>{props.label}</span>,
  Modal: () => null,
}));
vi.mock("./WorkloadApi", () => ({ JwtSvidFields: () => null, defaultJwtSvid: vi.fn() }));
vi.mock("./icons", () => ({ Icon: () => null }));

import { AuthEditor } from "./AuthEditor";

const EMPTY = { kind: "template", value: "" } as const;

function wsse(config: Partial<WsseConfig>): AuthConfig {
  return { type: "wsse", config: { username: "alice", password: EMPTY, password_type: "password_digest", ...config } };
}

afterEach(cleanup);

describe("WS-Security signature editor", () => {
  it("turns the X.509 signature on with a PEM identity and a Timestamp", () => {
    const onChange = vi.fn();
    render(<AuthEditor value={wsse({ timestamp_ttl_secs: null })} onChange={onChange} workspaceId="ws-1" />);
    fireEvent.click(screen.getByLabelText("Sign the Body, the Timestamp and the UsernameToken"));
    const next = onChange.mock.calls.at(-1)?.[0] as Extract<AuthConfig, { type: "wsse" }>;
    expect(next.config.signature).toEqual({ identity: { format: "pem", cert_chain_pem: "", private_key_pem: EMPTY }, algorithm: "auto" });
    expect(next.config.timestamp_ttl_secs).toBe(300);
  });

  it("shows the key fields for each identity format and switches between them", () => {
    const onChange = vi.fn();
    const signed = wsse({ signature: { identity: { format: "pem", cert_chain_pem: "", private_key_pem: EMPTY }, algorithm: "auto" } });
    const { rerender } = render(<AuthEditor value={signed} onChange={onChange} workspaceId="ws-1" />);
    expect(screen.getByText("Private key (PEM: RSA of at least 2048 bits, or EC P-256)")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Signing key format"), { target: { value: "pkcs12" } });
    const next = onChange.mock.calls.at(-1)?.[0] as AuthConfig;
    expect(next).toMatchObject({ config: { signature: { identity: { format: "pkcs12", bundle_b64: EMPTY, password: EMPTY } } } });
    rerender(<AuthEditor value={next} onChange={onChange} workspaceId="ws-1" />);
    expect(screen.getByText("Bundle password")).toBeTruthy();
    expect(screen.getByText("Choose .p12 / .pfx…")).toBeTruthy();
  });

  it("hides the username and password when the UsernameToken is off", () => {
    const onChange = vi.fn();
    const { rerender } = render(<AuthEditor value={wsse({})} onChange={onChange} workspaceId="ws-1" />);
    expect(screen.getByText("Password")).toBeTruthy();
    fireEvent.click(screen.getByLabelText("Send a UsernameToken"));
    const next = onChange.mock.calls.at(-1)?.[0] as AuthConfig;
    expect(next).toMatchObject({ config: { username_token: false } });
    rerender(<AuthEditor value={next} onChange={onChange} workspaceId="ws-1" />);
    expect(screen.queryByText("Password")).toBeNull();
  });
});
