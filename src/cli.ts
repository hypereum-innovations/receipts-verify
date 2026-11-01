#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * `hv` — the Hivemind Receipts command line.
 *   hv verify receipt.scitt [--checkpoint file] [--disclosure file.json] [--trust roots.json] [--json]
 *   hv verify-bundle bundle.json --trust roots.json
 *   hv capsule <statement.scitt>          print the capsule JSON view (JCS)
 *   hv keygen --kid my-key [--ed25519]    write a local signer + COSE key
 * Verification is Class 1: offline, deterministic, no calls to Hypereum.
 */
import { promises as fs } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { parseSign1 } from './core/cose.js';
import { capsuleJsonView, parseCapsule, type Disclosure } from './core/capsule.js';
import {
  canonicalizeJson,
  computeDeterministicRunId,
  formatReport,
  verifyReceiptBundle,
  type TrustRoots,
} from './core/verify.js';
import { LocalSigner, cborEncodeTrustKey, publicKeyFromCoseKey, decodeCoseKey } from './core/trust.js';

export interface TrustFile {
  issuers: Array<{
    kid: string;
    cose_key: string;
    tier?: 'T0' | 'T1' | 'T2' | 'T3' | string | null | undefined;
    display: string;
    operated_by?: 'hypereum' | 'customer' | string | null | undefined;
  }>;
  log_keys: Array<{ kid: string; cose_key: string }>;
  note_verifiers: string[];
  witness_policy?: { quorum: number; witnesses: Array<{ name: string; verifier: string }> };
  counter_signers?: Array<{ kid: string; cose_key: string }>;
}

export function trustFromFile(file: TrustFile): TrustRoots {
  const issuers = new Map();
  for (const i of file.issuers) {
    const { key, alg } = publicKeyFromCoseKey(decodeCoseKey(Buffer.from(i.cose_key, 'base64url')));
    const tier = typeof i.tier === 'string' && i.tier.trim().length > 0 ? i.tier.trim() : undefined;
    const operatedBy =
      typeof i.operated_by === 'string' && i.operated_by.trim().length > 0 ? i.operated_by.trim() : undefined;
    issuers.set(i.kid, {
      kid: i.kid,
      key,
      alg,
      ...(tier ? { tier } : {}),
      ...(operatedBy ? { operatedBy } : {}),
      display: i.display,
    });
  }
  const logKeys = new Map();
  for (const l of file.log_keys) {
    const { key, alg } = publicKeyFromCoseKey(decodeCoseKey(Buffer.from(l.cose_key, 'base64url')));
    logKeys.set(l.kid, { key, alg });
  }
  const trust: TrustRoots = {
    issuers,
    logKeys,
    noteVerifiers: file.note_verifiers,
    witnessPolicy: file.witness_policy ?? null,
    canonicalJson: canonicalizeJson(file),
  };
  if (file.counter_signers?.length) {
    trust.counterSigners = new Map();
    for (const c of file.counter_signers) {
      const { key, alg } = publicKeyFromCoseKey(decodeCoseKey(Buffer.from(c.cose_key, 'base64url')));
      trust.counterSigners.set(c.kid, { key, alg });
    }
  }
  return trust;
}

function arg(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
}

export async function hvMain(argv: string[]): Promise<number> {
  const [cmd, target] = argv;
  if (cmd === 'keygen') {
    const kid = arg(argv, 'kid') ?? 'issuer-1';
    const signer = LocalSigner.generate(argv.includes('--ed25519') ? 'Ed25519' : 'ES256', kid);
    await fs.writeFile(`${kid}.pem`, signer.exportPrivatePem(), { mode: 0o600 });
    await fs.writeFile(`${kid}.cose`, cborEncodeTrustKey(signer));
    console.log(`wrote ${kid}.pem (private) and ${kid}.cose (public COSE_Key, kid=${kid})`);
    return 0;
  }
  if (cmd === 'capsule' && target) {
    const parsed = parseSign1(await fs.readFile(target));
    if (!parsed.payload) throw new Error('detached statement: supply the payload to inspect');
    console.log(capsuleJsonView(parseCapsule(parsed.payload)));
    return 0;
  }
  if ((cmd === 'verify' || cmd === 'verify-bundle') && target) {
    const trustPath = arg(argv, 'trust');
    if (!trustPath) throw new Error('--trust roots.json is required (verification never trusts the network)');
    const trust = trustFromFile(JSON.parse(await fs.readFile(trustPath, 'utf8')) as TrustFile);
    let statement: Buffer;
    let checkpoint = arg(argv, 'checkpoint') ? await fs.readFile(arg(argv, 'checkpoint')!, 'utf8') : undefined;
    if (cmd === 'verify-bundle') {
      const bundle = JSON.parse(await fs.readFile(target, 'utf8')) as { entry: string; checkpoint: string };
      statement = Buffer.from(bundle.entry, 'base64');
      checkpoint = bundle.checkpoint;
    } else {
      statement = await fs.readFile(target);
    }
    const disclosurePath = arg(argv, 'disclosure');
    const disclosure = disclosurePath
      ? (JSON.parse(await fs.readFile(disclosurePath, 'utf8')) as Disclosure)
      : undefined;
    const report = verifyReceiptBundle(
      {
        statement,
        ...(checkpoint ? { checkpoint } : {}),
        ...(disclosure ? { disclosure } : {}),
      },
      trust,
    );
    console.log(argv.includes('--json') ? JSON.stringify(report, (_k, v) => (Buffer.isBuffer(v) ? v.toString('base64') : v), 2) : formatReport(report));
    return report.verdict === 'VERIFIED' ? 0 : 1;
  }
  console.error('usage: hv verify|verify-bundle|capsule|keygen ... (see docs/receipts)');
  return 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void hvMain(process.argv.slice(2)).then((code) => process.exit(code));
}
