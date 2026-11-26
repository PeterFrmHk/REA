import { ok as resultOk } from "../../../src/domain/result.js";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createServer } from "../../../src/server/createServer.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { cases } from "../../fixtures/f1ProofBoundary.fixture.js";
describe("F1 in-memory MCP proof applicability", () => {
  it.each(cases)("%s", async (_, ready, make) => {
    const {input, ledger} = make();
    expect(ledger.status === "ready").toBe(ready);
    let unexpectedCalls = 0;
    const session = createTestBinarySession(() => ({
      execute: async () => { unexpectedCalls++; throw new Error("UNEXPECTED_PROVIDER_CALL"); },
      close: () => Promise.resolve(resultOk(null)),
    }));
    const server = createServer({kind:"session", session});
    const client = new Client({name:"f1-proof-boundary",version:"1"});
    const [ct, st] = InMemoryTransport.createLinkedPair();
    try {
      await server.connect(st); await client.connect(ct);
      const result = await client.callTool({name:"build_reconstruction_obligation_ledger",arguments:input});
      expect(result.isError).not.toBe(true);
      const evidence = parseEvidence(result.structuredContent);
      expect(evidence.operation).toBe("build_reconstruction_obligation_ledger");
      expect(evidence.normalized_result).toEqual(ledger);
      expect(unexpectedCalls).toBe(0);
    } finally { await client.close(); await server.close(); await session.close(); }
  });
});
