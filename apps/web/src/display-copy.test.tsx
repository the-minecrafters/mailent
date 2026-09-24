import { describe, expect, it } from "vitest";
import { domainFromTitle, liveCheckMessage } from "./display-copy";

describe("saved results", () => {
  it("extracts the domain from old and new generated titles for scheduling", () => {
    expect(domainFromTitle("mail.company.test Infrastructure Assessment")).toBe(
      "mail.company.test",
    );
    expect(domainFromTitle("mail.company.test Domain check")).toBe(
      "mail.company.test",
    );
    expect(domainFromTitle("  mail.company.test  ")).toBe("mail.company.test");
  });
  it("keeps failed and mismatched checks inconclusive in plain language", () => {
    expect(
      liveCheckMessage("Probe failed or is incomplete; no fix established"),
    ).toBe("The check failed or is incomplete. The fix has not been verified.");
    expect(
      liveCheckMessage(
        "Passive observation saw TLSv1.2; active probe negotiated TLSv1.3",
      ),
    ).toBe("The captured connection used TLSv1.2; the live check used TLSv1.3");
    expect(
      liveCheckMessage(
        "Unexpected certificate response from mail.company.test",
      ),
    ).toBe("Unexpected certificate response from mail.company.test");
  });
});
