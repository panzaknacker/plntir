export const sessionFixture = {
  account_id: "acct_owner", device_id: "device_mac", expires_at: "2026-10-04T12:00:00Z",
  idle_expires_at: "2026-09-04T12:30:00Z", step_up_active: false, step_up_expires_at: null,
};

export const filesFixture = {
  items: [
    { id: "file_clean", filename: "Bericht.pdf", owner_account_id: "acct_owner", logical_size_bytes: 1_024, scan_state: "clean", state: "active", version: 2 },
    { id: "file_bad", filename: "Fund.bin", owner_account_id: "acct_contact", logical_size_bytes: 2_048, scan_state: "malware", state: "active", version: 1 },
  ],
  next_cursor: null,
};
