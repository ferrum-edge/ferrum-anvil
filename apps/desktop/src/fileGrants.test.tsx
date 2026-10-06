// The renderer never hands a file path to a file command: files come from the
// backend's own native dialog (`file_choose`) as opaque grants, and only the
// grant goes back. The Rust side is covered by crates/anvil-app/tests/
// file_grants.rs and the native E2E spec 10-file-grants.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import capabilities from "../src-tauri/capabilities/default.json";
import type { AuthConfig, TlsProfile } from "./generated/contracts";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn(), ask: vi.fn() }));

import { api } from "./api";
import { TlsForm } from "./Dialogs";
import { AuthEditor, PemFromFile } from "./AuthEditor";

const GRANT = { token: "fg-0123456789abcdef0123456789abcdef", file_name: "ca.pem" };
const SECRET = { id: "secret-id", label: "key.pem" };
const CERTIFICATE = "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n";

function tlsProfile(): TlsProfile {
  return {
    id: "t",
    workspace_id: "ws",
    name: "p",
    verify: true,
    use_system_roots: true,
    extra_roots_pem: [],
    bindings: [],
  } as unknown as TlsProfile;
}

afterEach(() => {
  cleanup();
  invoke.mockReset();
});

/** Every argument object sent to a command, flattened one level (spec inputs nest). */
function argKeys(): string[] {
  return invoke.mock.calls.flatMap(([, args]) =>
    Object.entries((args ?? {}) as Record<string, unknown>).flatMap(([k, v]) => (v && typeof v === "object" && !Array.isArray(v) ? [k, ...Object.keys(v)] : [k])),
  );
}

describe("file grants in the renderer", () => {
  it("asks the backend for the dialog and returns its grant", async () => {
    invoke.mockResolvedValueOnce([GRANT]);
    expect(await api.chooseCertificateFile()).toEqual(GRANT);
    expect(invoke).toHaveBeenLastCalledWith("certificate_file_choose", undefined);
    invoke.mockResolvedValueOnce([]);
    expect(await api.chooseFile("bundle_export", { file_name: "backup.anvil" })).toBeNull();
    expect(invoke).toHaveBeenLastCalledWith("file_choose", { purpose: "bundle_export", options: { file_name: "backup.anvil", multiple: false } });
  });

  it("passes only the grant to file commands", async () => {
    invoke.mockResolvedValue(undefined);
    const t = GRANT.token;
    await api.readCertificateFile(t);
    await api.importPrivateKeyFile(t, "ws", "key");
    await api.importPkcs12File(t, "ws", "p12");
    await api.attachmentAdd(t, null);
    await api.importPreview(t, null, "duplicate");
    await api.importApply(t, null, "duplicate");
    await api.exportToPath(null, "share_safely", null, t);
    await api.addDataset("ws", t, "users", []);
    await api.exportLoadReport("run", "json", t);
    await api.exportRunReport("run", "junit", t);
    await api.specPreview({ kind: "file", grant: t }, {} as never, { kind: "new_workspace" });
    expect(argKeys()).not.toContain("path");
    for (const [, args] of invoke.mock.calls) expect(JSON.stringify(args)).toContain(t);
  });

  it("loads a CA file through a grant, never a path", async () => {
    invoke.mockImplementation(async (cmd: string) => {
      if (cmd === "certificate_file_choose") return [GRANT];
      if (cmd === "read_certificate_file") return CERTIFICATE;
      throw new Error(`unexpected ${cmd}`);
    });
    const onChange = vi.fn();
    const p = tlsProfile();
    render(<TlsForm p={p} onChange={onChange} />);
    fireEvent.click(screen.getByText("Add CA from file…"));
    await waitFor(() => expect(onChange).toHaveBeenCalled());
    expect(invoke.mock.calls.map(([cmd]) => cmd)).toEqual([
      "certificate_file_choose",
      "read_certificate_file",
    ]);
    expect(invoke.mock.calls[0][1]).toBeUndefined();
    expect(invoke.mock.calls[1][1]).toEqual({ grant: GRANT.token });
    expect(onChange.mock.calls[0][0].extra_roots_pem).toEqual([CERTIFICATE]);
  });

  it("loads a JWT signing key using only a vault reference and fixed native purpose", async () => {
    invoke.mockImplementation(async (cmd: string) => {
      if (cmd === "private_key_file_choose") return [{ ...GRANT, file_name: "key.pem" }];
      if (cmd === "import_private_key_file") return SECRET;
      throw new Error(`unexpected ${cmd}`);
    });
    const onChange = vi.fn();
    const auth: AuthConfig = {
      type: "jwt",
      algorithm: "RS256",
      signing_key: { kind: "template", value: "" },
      claims: {},
    };
    render(<AuthEditor value={auth} workspaceId="ws" onChange={onChange} />);
    fireEvent.click(screen.getByText("Load private key file into the vault"));
    await waitFor(() => expect(onChange).toHaveBeenCalledWith({
      ...auth,
      signing_key: { kind: "secret", secret: SECRET },
    }));
    expect(invoke.mock.calls).toEqual([
      ["private_key_file_choose", undefined],
      ["import_private_key_file", { grant: GRANT.token, workspaceId: "ws", label: "key.pem" }],
    ]);
    expect(argKeys()).not.toContain("purpose");
    expect(argKeys()).not.toContain("storeAsSecret");
    expect(argKeys()).not.toContain("base64");
  });

  it("loads a TLS certificate chain and private key through their distinct commands", async () => {
    invoke.mockImplementation(async (cmd: string) => {
      if (cmd === "certificate_file_choose" || cmd === "private_key_file_choose") return [GRANT];
      if (cmd === "read_certificate_file") return CERTIFICATE;
      if (cmd === "import_private_key_file") return SECRET;
      throw new Error(`unexpected ${cmd}`);
    });
    const onChange = vi.fn();
    const p: TlsProfile = {
      ...tlsProfile(),
      client_identity: {
        format: "pem",
        cert_chain_pem: "",
        private_key_pem: { kind: "template", value: "" },
      },
    };
    const view = render(<TlsForm p={p} onChange={onChange} />);
    fireEvent.click(screen.getByText("Load certificate file…"));
    await waitFor(() => expect(onChange).toHaveBeenCalledTimes(1));
    const withCertificate = onChange.mock.calls[0][0] as TlsProfile;
    expect(withCertificate.client_identity).toMatchObject({ cert_chain_pem: CERTIFICATE });
    view.rerender(<TlsForm p={withCertificate} onChange={onChange} />);
    fireEvent.click(screen.getByText("Load private key file into the vault"));
    await waitFor(() => expect(onChange).toHaveBeenCalledTimes(2));
    expect(onChange.mock.calls[1][0].client_identity).toEqual({
      format: "pem",
      cert_chain_pem: CERTIFICATE,
      private_key_pem: { kind: "secret", secret: SECRET },
    });
    expect(invoke.mock.calls.map(([cmd]) => cmd)).toEqual([
      "certificate_file_choose",
      "read_certificate_file",
      "private_key_file_choose",
      "import_private_key_file",
    ]);
    expect(argKeys()).not.toContain("purpose");
    expect(argKeys()).not.toContain("storeAsSecret");
  });

  it("keeps PKCS#12 vault-only with a reference returned to the TLS form", async () => {
    invoke.mockImplementation(async (cmd: string) => {
      if (cmd === "file_choose") return [{ ...GRANT, file_name: "client.p12" }];
      if (cmd === "import_pkcs12_file") return SECRET;
      throw new Error(`unexpected ${cmd}`);
    });
    const onChange = vi.fn();
    const p: TlsProfile = {
      ...tlsProfile(),
      client_identity: {
        format: "pkcs12",
        bundle_b64: { kind: "template", value: "" },
        password: { kind: "template", value: "" },
      },
    };
    render(<TlsForm p={p} onChange={onChange} />);
    fireEvent.click(screen.getByText("Choose .p12 / .pfx…"));
    await waitFor(() => expect(onChange).toHaveBeenCalled());
    expect(onChange.mock.calls[0][0].client_identity.bundle_b64).toEqual({
      kind: "secret",
      secret: SECRET,
    });
    expect(invoke).toHaveBeenLastCalledWith("import_pkcs12_file", {
      grant: GRANT.token,
      workspaceId: "ws",
      label: "client.p12",
    });
    expect(argKeys()).not.toContain("storeAsSecret");
    expect(argKeys()).not.toContain("base64");
  });

  it("cancellation and ingestion failure leave no private-key value in the UI", async () => {
    const onSecret = vi.fn();
    render(<PemFromFile label="Load key" workspaceId="ws" onSecret={onSecret} />);
    invoke.mockResolvedValueOnce([]);
    fireEvent.click(screen.getByText("Load key"));
    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(1));
    expect(onSecret).not.toHaveBeenCalled();
    invoke.mockResolvedValueOnce([GRANT]).mockRejectedValueOnce("selection expired");
    fireEvent.click(screen.getByText("Load key"));
    await waitFor(() => expect(screen.getByText("selection expired")).toBeTruthy());
    expect(onSecret).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain("PRIVATE KEY");
  });

  it("native PEM entry points expose no renderer disposition or role selector", () => {
    const sources = import.meta.glob("../src-tauri/src/*.rs", {
      query: "?raw",
      import: "default",
      eager: true,
    }) as Record<string, string>;
    const native = sources["../src-tauri/src/commands.rs"];
    const dialogs = sources["../src-tauri/src/cmd_files.rs"];
    const registration = sources["../src-tauri/src/lib.rs"];
    for (const [name, purpose] of [
      ["certificate_file_choose", "PemCertificate"],
      ["private_key_file_choose", "PemPrivateKey"],
    ]) {
      const command = dialogs.split(`pub async fn ${name}(`)[1].split("\n}")[0];
      const signature = command.split(") ->")[0];
      expect(signature).not.toMatch(/purpose|options|title|path/);
      expect(command).toContain(`FilePurpose::${purpose}`);
      expect(registration).toContain(`cmd_files::${name},`);
    }
    const privateSignature = native.split("pub async fn import_private_key_file(")[1];
    expect(privateSignature.split("\n}")[0]).not.toMatch(/store_as_secret|base64|purpose:/);
    expect(privateSignature.split("\n}")[0]).toContain("R<SecretRef>");
    expect(dialogs).toContain("general_purpose(purpose)?;");
    expect(dialogs).toContain("PEM files require their dedicated native chooser");
    expect(registration).not.toContain("commands::read_text_file,");
    expect(native).not.toContain("store_as_secret");
  });

  it("does not let the webview open a file dialog or the filesystem", () => {
    const perms = capabilities.permissions as string[];
    expect(perms).not.toContain("dialog:allow-save");
    expect(perms).not.toContain("dialog:allow-open");
    expect(perms).not.toContain("dialog:default");
    expect(perms.filter((p) => p.startsWith("fs:"))).toEqual([]);
  });

  it("uses the dialog plugin only for confirmations", () => {
    const sources = import.meta.glob(["./*.tsx", "./*.ts", "!./*.test.tsx", "!./*.test.ts"], { query: "?raw", import: "default", eager: true }) as Record<string, string>;
    const importers: Record<string, string[]> = {};
    for (const [file, text] of Object.entries(sources)) {
      for (const m of text.matchAll(/import\s*\{([^}]*)\}\s*from\s*"@tauri-apps\/plugin-dialog"/g)) {
        importers[file] = m[1].split(",").map((s) => s.trim()).filter(Boolean);
      }
    }
    expect(importers).toEqual({ "./Workbench.tsx": ["ask"], "./ScopeSettings.tsx": ["ask"] });
  });
});
