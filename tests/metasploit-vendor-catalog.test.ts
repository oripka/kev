import { describe, expect, it } from "vitest";

import { matchVendorProductByTitle } from "../server/utils/metasploitVendorCatalog";

describe("matchVendorProductByTitle", () => {
  it("matches vendor and product names from the catalog", () => {
    const text =
      "Proof-of-concept exploit targeting Zoho ManageEngine ServiceDesk Plus remote code execution";

    expect(matchVendorProductByTitle(text)).toEqual({
      vendor: "Zoho",
      product: "ManageEngine ServiceDesk Plus (SDP) / SupportCenter Plus",
    });
  });

  it("ignores generic titles that do not map to a specific product", () => {
    const text = "Exploit affecting multiple unspecified products across several vendors";

    expect(matchVendorProductByTitle(text)).toBeNull();
  });
});
