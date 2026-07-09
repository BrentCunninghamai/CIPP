#!/usr/bin/env node
/**
 * CIPP Bastion sealing tool.
 *
 * Seals partner-only HTML into docs/partner-content.json using an envelope
 * scheme: the content is encrypted once with a random AES-256-GCM content
 * key, and that key is wrapped per-partner with a KEK derived from each
 * partner's access code (PBKDF2-SHA256, 600k iterations minimum).
 *
 * Uses Node's WebCrypto (globalThis.crypto.subtle) so the bytes produced here
 * are decrypted by the exact same primitives docs/assets/gate.js uses in the
 * browser.
 *
 * Safety rails (all fail closed):
 *   - Codes must match the gen-code format unless --allow-custom-codes is
 *     passed (custom codes must still be >= 16 chars). This blocks weak
 *     passphrases and stray metadata values from becoming key slots.
 *   - Keys starting with "_" are rejected outright (a "_comment" style key
 *     would otherwise become a real slot keyed by a public string).
 *   - The public demo code is refused except for the demo-only seal
 *     ({"demo": <demo code>} and nothing else).
 *   - Duplicate partner ids and duplicate codes are rejected.
 *   - Partner ids are NOT published: each slot gets a random opaque tag, and
 *     the id→tag mapping is printed for your records.
 *   - The bundle is self-checked (every code, via the shipped gate.js,
 *     against the serialized JSON) BEFORE it is written to disk.
 *
 * Commands:
 *   gen-code [--count N]
 *       Generate strong random access codes (~122 bits, grouped base32).
 *
 *   seal --content <file.html> --codes <codes.json> [--out <bundle.json>]
 *        [--iterations N] [--allow-custom-codes]
 *       Seal content for every partner in codes.json:
 *         { "partner-id": "ACCESS-CODE", ... }
 *       Always generates a fresh content key, so resealing without a partner
 *       revokes them even if they kept the old bundle. codes.json is a SECRET
 *       distribution list — never commit it (gitignored by default).
 *
 *   verify [--code <ACCESS-CODE>] [--bundle <bundle.json>]
 *       Prove a code unlocks the bundle (prints the matching slot tag).
 *       Without --code the code is read from stdin, which keeps real codes
 *       out of shell history:  node tools/pages-gate/encrypt.mjs verify
 *
 * Examples:
 *   node tools/pages-gate/encrypt.mjs gen-code --count 3
 *   node tools/pages-gate/encrypt.mjs seal \
 *     --content tools/pages-gate/partner-content.example.html \
 *     --codes tools/pages-gate/codes.local.json
 *   node tools/pages-gate/encrypt.mjs verify   # then paste the code + Enter
 */
import { readFile, writeFile } from 'node:fs/promises'
import { randomBytes } from 'node:crypto'
import { createRequire } from 'node:module'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..', '..')
const DEFAULT_BUNDLE = path.join(repoRoot, 'docs', 'partner-content.json')
const MIN_ITERATIONS = 600_000
const subtle = globalThis.crypto.subtle

// Public demo code — committed in codes.example.json so the gate is
// demonstrable out of the box. seal() refuses it for anything except the
// demo-only bundle, and the CI guard blocks production bundles it can open.
export const DEMO_CODE = 'T1CSP-DEMO2-ACCES-SCODE-ROTAT-EMENOW'
// gen-code output shape: T1CSP- then five dash-separated groups of five
// characters from the unambiguous base32 alphabet below.
const CODE_FORMAT = /^T1CSP-[2-9A-HJKMNP-TV-Z]{5}(-[2-9A-HJKMNP-TV-Z]{5}){4}$/

// The gate is a classic script exporting via module.exports; require() it so
// every check exercises the very code partners run in the browser.
const require = createRequire(import.meta.url)
const BastionGate = require(path.join(repoRoot, 'docs', 'assets', 'gate.js'))

const b64 = (buf) => Buffer.from(buf).toString('base64')

function parseArgs(argv) {
  const [cmd, ...rest] = argv
  const opts = {}
  for (let i = 0; i < rest.length; i++) {
    if (!rest[i].startsWith('--')) fail(`Unexpected argument: ${rest[i]}`)
    const key = rest[i].slice(2)
    if (rest[i + 1] === undefined || rest[i + 1].startsWith('--')) {
      opts[key] = true // boolean flag
    } else {
      opts[key] = rest[i + 1]
      i++
    }
  }
  return { cmd, opts }
}

function fail(msg) {
  console.error(`error: ${msg}\n`)
  console.error('Run with no arguments for usage.')
  process.exit(1)
}

/** ~122-bit access code in grouped Crockford-style base32 (no 0/O/1/I/L/U).
 *  Rejection sampling avoids modulo bias. */
function generateCode() {
  const alphabet = '23456789ABCDEFGHJKMNPQRSTVWXYZ' // 30 chars, unambiguous
  const limit = 256 - (256 % alphabet.length) // 240: highest unbiased byte
  let code = ''
  while (code.length < 25) {
    for (const byte of randomBytes(32)) {
      if (byte < limit) code += alphabet[byte % alphabet.length]
      if (code.length === 25) break
    }
  }
  return `T1CSP-${code.match(/.{5}/g).join('-')}`
}

async function deriveKek(code, salt, iterations) {
  const material = await subtle.importKey(
    'raw',
    new TextEncoder().encode(BastionGate.normalizeCode(code)),
    'PBKDF2',
    false,
    ['deriveKey']
  )
  return subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  )
}

/** JSON.parse silently keeps only the LAST value for duplicated keys, which
 *  would lock a partner out without any warning — detect and reject. Codes
 *  files are flat {string: string} objects, so a quote-aware key scan is
 *  reliable here. */
function assertNoDuplicateKeys(rawJson, parsed) {
  const keys = [...rawJson.matchAll(/"((?:[^"\\]|\\.)*)"\s*:/g)].map((m) => m[1])
  const unique = new Set(keys)
  if (keys.length !== unique.size || unique.size !== Object.keys(parsed).length) {
    fail('codes file has duplicate or ambiguous keys — every partner id must be unique')
  }
}

function validateEntries(entries, allowCustom) {
  const seenCodes = new Set()
  const isDemoOnly =
    entries.length === 1 &&
    entries[0][0] === 'demo' &&
    BastionGate.normalizeCode(entries[0][1]) === DEMO_CODE

  for (const [id, code] of entries) {
    if (id.startsWith('_')) {
      fail(
        `key "${id}" looks like metadata, but seal would turn it into a REAL key slot ` +
          `whose "access code" is whatever string it holds. Remove it from the codes file.`
      )
    }
    if (typeof code !== 'string') fail(`code for "${id}" is not a string`)
    const norm = BastionGate.normalizeCode(code)
    if (norm === DEMO_CODE && !isDemoOnly) {
      fail(
        `the PUBLIC demo code is in your codes file under "${id}". It is committed ` +
          `world-readable in codes.example.json — anyone could open the vault. ` +
          `Generate real codes with gen-code.`
      )
    }
    if (norm !== DEMO_CODE && !CODE_FORMAT.test(norm)) {
      if (!allowCustom) {
        fail(
          `code for "${id}" does not match the gen-code format (T1CSP-XXXXX-…). ` +
            `Use gen-code, or pass --allow-custom-codes if you really need a custom passphrase.`
        )
      }
      if (norm.length < 16) {
        fail(
          `custom code for "${id}" is too short (< 16 chars) for a public, offline-attackable bundle`
        )
      }
    }
    if (seenCodes.has(norm)) fail(`duplicate access code detected (second use on "${id}")`)
    seenCodes.add(norm)
  }
  return isDemoOnly
}

async function seal(opts) {
  if (!opts.content || !opts.codes) fail('seal requires --content and --codes')
  const iterations = opts.iterations ? Number(opts.iterations) : MIN_ITERATIONS
  if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS) {
    fail(
      `--iterations must be an integer >= ${MIN_ITERATIONS} (the value all published docs promise)`
    )
  }
  const html = await readFile(opts.content, 'utf8')
  const rawCodes = await readFile(opts.codes, 'utf8')
  const codes = JSON.parse(rawCodes)
  assertNoDuplicateKeys(rawCodes, codes)
  const entries = Object.entries(codes)
  if (entries.length === 0) fail('codes file contains no partners')
  const isDemoOnly = validateEntries(entries, opts['allow-custom-codes'] === true)

  // Fresh content key every seal → resealing rotates the payload, which is
  // what makes removing a slot an actual revocation.
  const contentKeyRaw = randomBytes(32)
  const contentKey = await subtle.importKey('raw', contentKeyRaw, 'AES-GCM', false, ['encrypt'])
  const payloadIv = randomBytes(12)
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv: payloadIv },
    contentKey,
    new TextEncoder().encode(html)
  )

  // Partner ids are confidential (they name your Tier 1 roster) — publish a
  // random opaque tag per slot instead. 'demo' stays literal so the CI guard
  // can recognise the out-of-the-box demo bundle.
  const slots = []
  const tagById = new Map()
  for (const [id, code] of entries) {
    let tag = isDemoOnly && id === 'demo' ? 'demo' : randomBytes(4).toString('hex')
    while ([...tagById.values()].includes(tag)) tag = randomBytes(4).toString('hex')
    tagById.set(id, tag)
    const salt = randomBytes(16)
    const iv = randomBytes(12)
    const kek = await deriveKek(code, salt, iterations)
    const wrapped = await subtle.encrypt({ name: 'AES-GCM', iv }, kek, contentKeyRaw)
    slots.push({ id: tag, salt: b64(salt), iv: b64(iv), wrapped: b64(wrapped) })
  }

  const bundle = {
    version: 1,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations },
    slots,
    payload: { iv: b64(payloadIv), ciphertext: b64(ciphertext) },
  }

  // Self-check BEFORE anything touches disk, against the re-parsed serialized
  // JSON (what will actually be published), through the shipped gate code.
  const serialized = JSON.stringify(bundle, null, 2) + '\n'
  const republished = JSON.parse(serialized)
  for (const [id, code] of entries) {
    const res = await BastionGate.unlock(republished, code)
    if (!res || res.slotId !== tagById.get(id) || res.html !== html) {
      fail(`self-check failed for partner "${id}" — nothing was written`)
    }
  }

  const out = opts.out || DEFAULT_BUNDLE
  await writeFile(out, serialized)

  console.log(`sealed ${entries.length} partner slot(s) -> ${path.relative(process.cwd(), out)}`)
  console.log('self-check passed: every code unlocks via docs/assets/gate.js')
  console.log('\npartner → published slot tag (keep with your codes file; ids are not published):')
  for (const [id, tag] of tagById) console.log(`  ${id} → ${tag}`)
  if (isDemoOnly) {
    console.log('\n⚠  DEMO SEAL: this bundle opens with the PUBLIC demo code.')
    console.log('   Rotate to real gen-code codes before sharing anything sensitive.')
  }
}

function readLineFromStdin() {
  return new Promise((resolve, reject) => {
    let data = ''
    if (process.stdin.isTTY) console.error('Enter access code (input is not echoed to any log):')
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (chunk) => {
      data += chunk
      const nl = data.indexOf('\n')
      if (nl !== -1) {
        process.stdin.pause()
        resolve(data.slice(0, nl))
      }
    })
    process.stdin.on('end', () => resolve(data))
    process.stdin.on('error', reject)
  })
}

async function verify(opts) {
  const code = typeof opts.code === 'string' ? opts.code : await readLineFromStdin()
  if (!BastionGate.normalizeCode(code)) fail('no access code provided')
  const bundlePath = typeof opts.bundle === 'string' ? opts.bundle : DEFAULT_BUNDLE
  const bundle = JSON.parse(await readFile(bundlePath, 'utf8'))
  const res = await BastionGate.unlock(bundle, code)
  if (res) {
    console.log(`OK: code unlocks slot tag "${res.slotId}" (${res.html.length} chars of content)`)
  } else {
    console.error('REJECTED: code does not unlock any slot')
    process.exit(2)
  }
}

function genCode(opts) {
  const count = opts.count ? Number(opts.count) : 1
  if (!Number.isInteger(count) || count < 1 || count > 100) fail('--count must be 1-100')
  for (let i = 0; i < count; i++) console.log(generateCode())
}

const { cmd, opts } = parseArgs(process.argv.slice(2))
switch (cmd) {
  case 'seal':
    await seal(opts)
    break
  case 'verify':
    await verify(opts)
    break
  case 'gen-code':
    genCode(opts)
    break
  default:
    console.log(
      [
        'CIPP Bastion sealing tool',
        '',
        'usage:',
        '  node tools/pages-gate/encrypt.mjs gen-code [--count N]',
        '  node tools/pages-gate/encrypt.mjs seal --content <file.html> --codes <codes.json> [--out <bundle.json>] [--iterations N] [--allow-custom-codes]',
        '  node tools/pages-gate/encrypt.mjs verify [--code <ACCESS-CODE>] [--bundle <bundle.json>]',
        '',
        'verify reads the code from stdin when --code is omitted (keeps codes out of shell history).',
      ].join('\n')
    )
    process.exit(cmd ? 1 : 0)
}
