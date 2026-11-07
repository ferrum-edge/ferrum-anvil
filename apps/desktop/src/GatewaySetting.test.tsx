// Renderer tests for the Ferrum gateway profile setting (jsdom; no engine): a
// request, folder or workspace setting that names a removed profile shows it
// as "removed profile", not an empty select, and can be cleared to inherit.
// Until the workspace's profiles are read, an unlisted id is shown as it is.
import { useState } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { IntegrationProfile, SettingsOverrides } from "./generated/contracts";
import { SettingsOverridesEditor, type Profiles } from "./RequestEditor";

afterEach(cleanup);

const gateway: IntegrationProfile = {
  id: "gw-1",
  workspace_id: "ws",
  name: "Edge",
  kind: "ferrum_gateway",
  hosts: [{ host: "gw.example" }],
  compatibility_id: "ferrum-edge-0.9.20",
  require_verified_tls: true,
  created_at: "2026-11-01T00:00:00Z",
  updated_at: "2026-11-01T00:00:00Z",
} as IntegrationProfile;

const profiles: Profiles = { tls: [], proxy: [], integrations: [gateway] };

let latest: SettingsOverrides = {};

function Harness(props: { initial: SettingsOverrides; loaded?: boolean }) {
  const [s, setS] = useState<SettingsOverrides>(props.initial);
  latest = s;
  return (
    <SettingsOverridesEditor
      value={s}
      onChange={(v) => {
        latest = v;
        setS(v);
      }}
      profiles={profiles}
      profilesLoaded={props.loaded ?? true}
    />
  );
}

function gatewaySelect(): HTMLSelectElement {
  return screen.getByText("Ferrum gateway profile").querySelector("select") as HTMLSelectElement;
}

const selectedLabel = () => gatewaySelect().selectedOptions[0]?.textContent;

describe("the Ferrum gateway profile setting", () => {
  it("shows a removed profile's id as such and clears it", () => {
    render(<Harness initial={{ integration_profile_id: "gw-gone" }} />);
    expect(gatewaySelect().value).toBe("gw-gone");
    expect(selectedLabel()).toBe("removed profile");
    const note = screen.getByRole("note", { name: "Removed gateway profile" });
    expect(note.textContent).toContain("gw-gone");

    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(latest.integration_profile_id).toBeNull();
    expect(gatewaySelect().value).toBe("");
    expect(selectedLabel()).toBe("inherit");
    expect(screen.queryByRole("note", { name: "Removed gateway profile" })).toBeNull();
    expect(Array.from(gatewaySelect().options).map((o) => o.textContent)).not.toContain("removed profile");
  });

  it("can also be cleared by choosing inherit or a saved profile", () => {
    render(<Harness initial={{ integration_profile_id: "gw-gone" }} />);
    fireEvent.change(gatewaySelect(), { target: { value: "gw-1" } });
    expect(latest.integration_profile_id).toBe("gw-1");
    expect(selectedLabel()).toBe("Edge (ferrum-edge-0.9.20)");
    expect(screen.queryByRole("note", { name: "Removed gateway profile" })).toBeNull();
  });

  it("says nothing for a saved profile or for inherit", () => {
    render(<Harness initial={{ integration_profile_id: "gw-1" }} />);
    expect(selectedLabel()).toBe("Edge (ferrum-edge-0.9.20)");
    expect(screen.queryByRole("note", { name: "Removed gateway profile" })).toBeNull();
    cleanup();
    render(<Harness initial={{}} />);
    expect(selectedLabel()).toBe("inherit");
    expect(screen.queryByRole("note", { name: "Removed gateway profile" })).toBeNull();
  });

  it("shows an unlisted id as it is, with nothing to clear, until the profiles are read", () => {
    const empty: Profiles = { tls: [], proxy: [], integrations: [] };
    const { rerender } = render(<SettingsOverridesEditor value={{ integration_profile_id: "gw-1" }} onChange={() => {}} profiles={empty} profilesLoaded={false} />);
    expect(gatewaySelect().value).toBe("gw-1");
    expect(selectedLabel()).toBe("gw-1");
    expect(Array.from(gatewaySelect().options).map((o) => o.textContent)).not.toContain("removed profile");
    expect(screen.queryByRole("note", { name: "Removed gateway profile" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Clear" })).toBeNull();
    // Without the signal the editor assumes the profiles are not read.
    rerender(<SettingsOverridesEditor value={{ integration_profile_id: "gw-1" }} onChange={() => {}} profiles={empty} />);
    expect(screen.queryByRole("button", { name: "Clear" })).toBeNull();
    // Read: the saved profile is listed by name.
    rerender(<SettingsOverridesEditor value={{ integration_profile_id: "gw-1" }} onChange={() => {}} profiles={profiles} profilesLoaded />);
    expect(selectedLabel()).toBe("Edge (ferrum-edge-0.9.20)");
    expect(screen.queryByRole("button", { name: "Clear" })).toBeNull();
  });
});
