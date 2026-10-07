import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { App, classify } from "./App";

const harness = vi.hoisted(() => ({ devices: [] as Array<Record<string, unknown>>, calls: [] as Array<{ command: string; args?: unknown }>, handlers: new Map<string, (event: { payload: unknown }) => void>(), failPairing: false }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn(async (command: string, args?: unknown) => {
  harness.calls.push({ command, args });
  if (command === "get_local_device") return { label: "Test PC", platform: "Windows", deviceId: "abc", fingerprint: "abc", protocolVersion: 1, identityStatus: "ready" };
  if (command === "list_devices") return harness.devices;
  if (command === "get_settings") return { appearance: "system", privacyPaused: false, activityRetentionDays: 7, startMinimized: false, notifications: true, trayBehavior: "minimize", lanEnabled: true };
  if (command === "get_diagnostics") return { identityStatus: "ready", trustDbStatus: "ready", secureStoreStatus: "available", lanStatus: "available", sessionStatus: "disconnected", platform: "Windows", protocolVersion: 1, appVersion: "0.1.0", lastError: null, privacyPaused: false };
  if (command === "get_activity") return [];
  if (command === "get_lan_endpoint") return "192.168.1.5:45678";
  if (command === "get_pairing_invitation_remaining") return 120;
  if (command === "create_pairing_invitation") return { payloadHex: "a60068434c4950504149520101025820", expiresInSeconds: 120 };
  if (command === "confirm_pairing") { if ((args as { accepted?: boolean } | undefined)?.accepted === false) throw "pairing_rejected"; if (harness.failPairing) throw "pairing_needs_repair"; return { state: "trusted", deviceId: "aa".repeat(32), label: "Office PC" }; }
  if (command === "send_text") return undefined;
  return undefined;
}) }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => { harness.handlers.set(name, handler); return () => harness.handlers.delete(name); }) }));
vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({ readText: vi.fn(async () => "manual text"), writeText: vi.fn(async () => undefined) }));

describe("desktop foundation", () => {
  afterEach(() => cleanup());
  beforeEach(() => { vi.clearAllMocks(); harness.devices = []; harness.calls = []; harness.handlers.clear(); harness.failPairing = false; });
  it("classifies text conservatively without interpreting it", () => {
    expect(classify("https://example.com/path")).toBe("URL");
    expect(classify("const x = 1;\nconsole.log(x)")).toBe("Code");
    expect(classify("ordinary words")).toBe("Text");
  });
  it("navigates real shell screens and keeps the initial route honest", async () => {
    render(<App />);
    await screen.findByText(/Move a thought/);
    fireEvent.click(screen.getByRole("button", { name: "Devices" }));
    expect(await screen.findByText("No trusted devices yet")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Help & Guide" }));
    await waitFor(() => expect(screen.getAllByRole("heading", { name: "Help & Guide" }).length).toBeGreaterThan(0));
    fireEvent.click(screen.getByRole("button", { name: "Add Device" }));
    expect(await screen.findByRole("button", { name: "Create pairing invitation" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Create pairing invitation" }));
    expect(await screen.findByText(/Expires in/)).toBeTruthy();
    expect(document.querySelector(".qr-frame svg")).toBeTruthy();
  });
  it("shows explicit read and clipboard privacy controls", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: /Read clipboard/i }));
    expect(await screen.findByText("manual text")).toBeTruthy();
  });
  it("marks system notifications unavailable instead of exposing an inert toggle", async () => {
    render(<App />);
    fireEvent.click(within(screen.getByRole("navigation", { name: "Main navigation" })).getByRole("button", { name: "Settings" }));
    expect(await screen.findByText("Not emitted in this build")).toBeTruthy();
    expect(screen.queryByRole("switch", { name: /notifications/i })).toBeNull();
  });
  it("renders an actual QR invitation and follows protocol-issued expiry/cancel state", async () => {
    render(<App />);
    fireEvent.click(within(screen.getByRole("navigation", { name: "Main navigation" })).getByRole("button", { name: "Add Device" }));
    fireEvent.click(await screen.findByRole("button", { name: "Create pairing invitation" }));
    expect(await screen.findByText("Expires in 2:00")).toBeTruthy();
    expect(document.querySelector(".qr-frame svg")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Cancel invitation" }));
    await waitFor(() => expect(harness.calls.some(call => call.command === "cancel_pairing_invitation")).toBe(true));
  });
  it("requires the affirmative SAS action before confirming trust", async () => {
    render(<App />);
    fireEvent.click(within(screen.getByRole("navigation", { name: "Main navigation" })).getByRole("button", { name: "Add Device" }));
    await waitFor(() => expect(harness.handlers.has("pairing-ready")).toBe(true));
    act(() => harness.handlers.get("pairing-ready")?.({ payload: { sas: "3857-12af-91c3-77d2", peerFingerprint: "f".repeat(64), role: "joiner" } }));
    expect(await screen.findByText("3857-12af-91c3-77d2")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Codes match" }));
    await waitFor(() => expect(harness.calls.some(call => call.command === "confirm_pairing" && (call.args as { accepted: boolean }).accepted)).toBe(true));
    expect(await screen.findByText("Device trusted")).toBeTruthy();
  });
  it("stops on a SAS mismatch without saving trust", async () => {
    render(<App />);
    fireEvent.click(within(screen.getByRole("navigation", { name: "Main navigation" })).getByRole("button", { name: "Add Device" }));
    await waitFor(() => expect(harness.handlers.has("pairing-ready")).toBe(true));
    act(() => harness.handlers.get("pairing-ready")?.({ payload: { sas: "3857-12af-91c3-77d2", peerFingerprint: "f".repeat(64), role: "issuer" } }));
    fireEvent.click(await screen.findByRole("button", { name: "Doesn’t match" }));
    expect(await screen.findByText("Pairing stopped")).toBeTruthy();
    expect(harness.calls.some(call => call.command === "confirm_pairing" && (call.args as { accepted: boolean }).accepted)).toBe(false);
  });
  it("shows repair guidance after a final-window pairing failure", async () => {
    harness.failPairing = true;
    render(<App />);
    fireEvent.click(within(screen.getByRole("navigation", { name: "Main navigation" })).getByRole("button", { name: "Add Device" }));
    await waitFor(() => expect(harness.handlers.has("pairing-ready")).toBe(true));
    act(() => harness.handlers.get("pairing-ready")?.({ payload: { sas: "3857-12af-91c3-77d2", peerFingerprint: "f".repeat(64), role: "joiner" } }));
    fireEvent.click(await screen.findByRole("button", { name: "Codes match" }));
    expect(await screen.findByText("Pairing incomplete · Needs repair")).toBeTruthy();
    expect(screen.queryByText("Device trusted")).toBeNull();
  });
  it("sends Compose text only to a selected trusted peer and explicitly supplied route", async () => {
    harness.devices = [{ id: "aa".repeat(32), label: "Office PC", platform: "Desktop", trustState: "trusted", connectivity: "offline", fingerprint: "aa".repeat(32), trustedAt: 1, minimumProtocol: 1 }];
    render(<App />);
    fireEvent.click(await screen.findByRole("tab", { name: /Compose/i }));
    fireEvent.change(screen.getByRole("textbox", { name: "Compose text" }), { target: { value: "hello securely" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Send to" }), { target: { value: "aa".repeat(32) } });
    fireEvent.change(screen.getByRole("textbox", { name: "Peer LAN address" }), { target: { value: "192.168.1.20:47831" } });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(harness.calls.some(call => call.command === "send_text" && (call.args as { text: string }).text === "hello securely")).toBe(true));
  });
});
