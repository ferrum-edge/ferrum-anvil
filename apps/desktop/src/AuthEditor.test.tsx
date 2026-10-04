import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { SendInput, TokenSummary } from "./api";
import type { AuthConfig } from "./generated/contracts";

const backend = vi.hoisted(() => ({
  status: vi.fn(),
  signIn: vi.fn(),
  signOut: vi.fn(),
}));
vi.mock("./api", () => ({
  api: {
    oauthTokenStatus: backend.status,
    oauthSignIn: backend.signIn,
    oauthSignOut: backend.signOut,
  },
  onOAuthFlow: vi.fn(async () => () => {}),
}));
vi.mock("./ui", () => ({
  SecretField: () => null,
  Modal: () => null,
}));
vi.mock("./WorkloadApi", () => ({ JwtSvidFields: () => null, defaultJwtSvid: vi.fn() }));
vi.mock("./icons", () => ({ Icon: () => null }));

import { AuthEditor } from "./AuthEditor";

const auth: AuthConfig = {
  type: "oauth2",
  config: {
    grant: "authorization_code_pkce",
    token_url: "http://localhost:8080/token",
    authorization_url: "https://issuer.example/authorize",
    client_id: "client",
    client_secret: { kind: "template", value: "" },
    scope: "orders.read",
    client_auth: "basic_header",
    refresh_skew_secs: 30,
  },
};
const input: SendInput = { workspace_id: "ws-1", request_id: "request-1", send_anyway: false };
const refusal = "the OAuth token endpoint requires HTTPS or literal-loopback HTTP";
const summary: TokenSummary = {
  token_type: "Bearer",
  expires_at: null,
  refresh_token_available: false,
};

function editor(signInInput: SendInput = input) {
  return (
    <AuthEditor
      value={auth}
      onChange={() => {}}
      workspaceId="ws-1"
      signInInput={signInInput}
    />
  );
}

afterEach(() => {
  cleanup();
  backend.status.mockReset();
  backend.signIn.mockReset();
  backend.signOut.mockReset();
});

test("OAuth guidance explains the draft literal HTTP restriction without a bypass", async () => {
  backend.status.mockResolvedValue(null);
  render(editor());
  expect(
    screen.getByText(/Candidate HTTP policy \(draft; owner approval pending\)/).textContent,
  ).toContain("localhost and other DNS names do not qualify for HTTP");
  expect(screen.getByText(/IPv4-mapped IPv6 loopback/).textContent).toContain(
    "every grant and refresh; there is no insecure override",
  );
  expect(screen.queryByRole("checkbox", { name: /insecure/i })).toBeNull();
  await waitFor(() => expect(backend.status).toHaveBeenCalledWith(input));
});

test("a rejected token status shows its configuration error", async () => {
  backend.status.mockRejectedValue(new Error(refusal));
  render(editor());
  expect((await screen.findByRole("alert")).textContent).toContain(refusal);
  expect(screen.getByText("status unavailable")).toBeTruthy();
  expect(screen.queryByText("not signed in")).toBeNull();
  expect(backend.signIn).not.toHaveBeenCalled();
});

test("an eligible uncached profile is signed out and browser refusal remains visible", async () => {
  backend.status.mockResolvedValue(null);
  backend.signIn.mockRejectedValue(new Error(refusal));
  render(editor());
  await waitFor(() => expect(backend.status).toHaveBeenCalledWith(input));
  expect(screen.getByText("not signed in")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Sign in with browser…" }));
  await screen.findByText(refusal);
  expect(backend.signIn).toHaveBeenCalledWith(input, expect.any(String));
  expect(screen.queryByRole("alert")).toBeNull();
});

test("a completed sign-in refreshes metadata and clears a status failure", async () => {
  backend.status.mockRejectedValueOnce(new Error(refusal)).mockResolvedValueOnce(summary);
  backend.signIn.mockResolvedValue({});
  render(editor());
  await screen.findByRole("alert");
  fireEvent.click(screen.getByRole("button", { name: "Sign in with browser…" }));
  await screen.findByText(/signed in · Bearer/);
  expect(screen.queryByRole("alert")).toBeNull();
  expect(backend.status).toHaveBeenCalledTimes(2);
});

test("a stale status rejection cannot overwrite a different request's current status", async () => {
  let rejectFirst: (error: Error) => void = () => {};
  backend.status
    .mockImplementationOnce(
      () => new Promise((_, reject) => {
        rejectFirst = reject;
      }),
    )
    .mockResolvedValueOnce(summary);
  const view = render(editor());
  await waitFor(() => expect(backend.status).toHaveBeenCalledTimes(1));
  view.rerender(editor({ ...input, request_id: "request-2" }));
  await screen.findByText(/signed in · Bearer/);
  await act(async () => {
    rejectFirst(new Error(refusal));
  });
  expect(screen.queryByRole("alert")).toBeNull();
  expect(screen.getByText(/signed in · Bearer/)).toBeTruthy();
});
