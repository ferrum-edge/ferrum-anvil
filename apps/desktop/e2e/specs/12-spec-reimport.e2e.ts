// Reimport a changed spec through the real UI and the production IPC: import
// a pasted OpenAPI description into a new workspace, then reimport its next
// version from the workspace picker. The review lists what changes; deleting
// the request the source no longer has is asked once more; the apply writes
// exactly that plan. Nothing is mocked and nothing is sent.
import { $, browser, expect } from "@wdio/globals";
import { invoke, waitForWorkbench } from "../helpers";

const V1 = JSON.stringify({
  openapi: "3.1.0",
  info: { title: "E2E reimport shop", version: "1" },
  servers: [{ url: "https://shop.example.invalid" }],
  paths: {
    "/orders": { get: { operationId: "listOrders", summary: "List orders", responses: { "200": { description: "ok" } } } },
    "/orders/{id}": {
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      get: { operationId: "getOrder", summary: "Get order", responses: { "200": { description: "ok" } } },
      delete: { operationId: "deleteOrder", summary: "Delete order", responses: { "204": { description: "gone" } } },
    },
  },
});

const V2 = JSON.stringify({
  openapi: "3.1.0",
  info: { title: "E2E reimport shop", version: "2" },
  servers: [{ url: "https://shop.example.invalid" }],
  paths: {
    "/orders": {
      get: { operationId: "listOrders", summary: "List all orders", responses: { "200": { description: "ok" } } },
      post: { operationId: "createOrder", summary: "Create order", responses: { "201": { description: "made" } } },
    },
    "/orders/{id}": {
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      get: { operationId: "getOrder", summary: "Get order", responses: { "200": { description: "ok" } } },
    },
  },
});

const dialog = (title: string) => `//div[@role="dialog"][@aria-label="${title}"]`;
const button = (title: string, label: string) => $(`${dialog(title)}//button[starts-with(normalize-space(), "${label}")]`);
// A request row's title is its name, then its URL on the next line.
const treeRow = (name: string) => $(`[role="treeitem"][title^="${name}"]`);

/** Set the open dialog's text area through React's own onChange path. */
async function paste(title: string, text: string): Promise<void> {
  await browser.execute(
    (label: string, value: string) => {
      const field = document.querySelector(`[role="dialog"][aria-label="${label}"] textarea`) as HTMLTextAreaElement;
      const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!;
      setter.call(field, value);
      field.dispatchEvent(new Event("input", { bubbles: true }));
    },
    title,
    text,
  );
}

/** Pick an entry of the workspace picker as a user's selection does (a change event). */
async function pickWorkspaceEntry(value: string): Promise<void> {
  await browser.execute((v: string) => {
    const select = document.querySelector('select[aria-label="Workspace"]') as HTMLSelectElement;
    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!;
    setter.call(select, v);
    select.dispatchEvent(new Event("change", { bubbles: true }));
  }, value);
}

type Source = { file_name: string; previous_import_ids?: string[]; source: { import_id: string } };
type TreeEntry = { name: string };

describe("reimporting a changed spec", () => {
  before(async () => {
    await waitForWorkbench();
  });

  it("updates the import from the new version the user reviewed", async () => {
    // Import the first version into a new workspace.
    await $('button[aria-label="Import"]').click();
    await $(dialog("Import")).waitForDisplayed();
    await paste("Import", V1);
    await button("Import", "Preview").click();
    const importButton = $(`${dialog("Import")}//button[normalize-space()="Import"]`);
    await importButton.waitForEnabled({ timeout: 30_000 });
    await importButton.click();
    await $(dialog("Import")).waitForDisplayed({ reverse: true, timeout: 30_000 });
    await treeRow("Delete order").waitForDisplayed({ timeout: 30_000 });
    const workspaceId = await $('select[aria-label="Workspace"]').getValue();
    const before = await invoke<Source[]>("spec_sources", { workspaceId });
    expect(before.err).toBeUndefined();
    expect(before.ok!.length).toBe(1);
    const firstImport = before.ok![0].source.import_id;

    // Reimport the next version from the workspace picker and review it.
    await pickWorkspaceEntry("__reimport");
    const title = "Reimport a changed spec";
    await $(dialog(title)).waitForDisplayed();
    await $(`${dialog(title)}//select`).waitForDisplayed();
    await paste(title, V2);
    await button(title, "Review changes").click();
    await $(`${dialog(title)}//legend[normalize-space()="No longer in the source"]`).waitForDisplayed({ timeout: 30_000 });
    await expect($(`${dialog(title)}//section[@aria-label="Reimport plan"]`)).toHaveText(expect.stringContaining("POST Create order"));

    // Deleting what the source no longer has is confirmed once more.
    await $(`${dialog(title)}//input[@aria-label="Delete Delete order"]`).click();
    await button(title, "Apply").click();
    await $(`${dialog(title)}//div[@role="alert"][contains(., "will be deleted from")]`).waitForDisplayed();
    await button(title, "Confirm and apply").click();
    await $(dialog(title)).waitForDisplayed({ reverse: true, timeout: 30_000 });

    // The workspace shows the new version: added, renamed upstream, deleted.
    await treeRow("Create order").waitForDisplayed({ timeout: 30_000 });
    await treeRow("List all orders").waitForDisplayed();
    await treeRow("Delete order").waitForDisplayed({ reverse: true });
    const tree = await invoke<TreeEntry[]>("tree_get", { workspaceId });
    expect(tree.err).toBeUndefined();
    expect(tree.ok!.map((n) => n.name).sort()).toEqual(["Create order", "Get order", "List all orders"]);
    const after = await invoke<Source[]>("spec_sources", { workspaceId });
    expect(after.ok!.length).toBe(1);
    expect(after.ok![0].previous_import_ids).toEqual([firstImport]);
  });
});
