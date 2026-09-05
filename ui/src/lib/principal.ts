// Thin re-export shim — `displayPrincipal` now lives in `~/lib/displayField`
// alongside its sibling helpers (`displayMachineIdentity`,
// `displayPrincipalCanonical`). See `displayField.ts` for the rationale and
// the full helper family. This file is preserved as a re-export so existing
// import paths in `ReceiptRow.tsx`, `ReceiptDetail.tsx`, and
// `PolicySimulator.tsx` continue to work unchanged.

export { displayPrincipal } from "~/lib/displayField";
