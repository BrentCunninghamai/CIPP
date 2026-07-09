/**
 * CIPP Bastion — partner access gate.
 *
 * Unlocks partner-only content sealed by tools/pages-gate/encrypt.mjs.
 *
 * Format (docs/partner-content.json):
 *   {
 *     version: 1,
 *     kdf: { name: "PBKDF2", hash: "SHA-256", iterations: 600000 },
 *     slots: [ { id, salt, iv, wrapped } ],          // one slot per partner
 *     payload: { iv, ciphertext }                    // AES-256-GCM over HTML
 *   }
 *
 * Envelope design (LUKS-style key slots):
 *   - The content is encrypted ONCE with a random 256-bit content key.
 *   - Each partner slot wraps that content key with a KEK derived from that
 *     partner's access code (PBKDF2-SHA256). GCM authentication means a wrong
 *     code fails the unwrap cleanly, so we can try slots in order.
 *   - Revoking one partner = reseal without their slot (rotate the content
 *     key, which `seal` always does).
 *
 * This file is dependency-free and runs unmodified in the browser (classic
 * script) and in Node >= 20 (require()) so the exact code path shipped to
 * partners is what the test suite exercises.
 */
'use strict'

var BastionGate = (function () {
  var subtle = globalThis.crypto && globalThis.crypto.subtle

  function b64ToBytes(s) {
    var bin = atob(s)
    var out = new Uint8Array(bin.length)
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  }

  function normalizeCode(code) {
    // NFKC so visually-identical codes pasted from PDFs/email compare equal.
    var c = String(code || '')
      .normalize('NFKC')
      .trim()
    // Issued codes (T1CSP-…) use an uppercase alphabet by design; case-fold
    // them so a code retyped in lowercase still works. Custom passphrases
    // (sealed with --allow-custom-codes) keep their case.
    if (/^t1csp-/i.test(c)) c = c.toUpperCase()
    return c
  }

  async function deriveKek(code, saltB64, kdf) {
    var material = await subtle.importKey(
      'raw',
      new TextEncoder().encode(normalizeCode(code)),
      'PBKDF2',
      false,
      ['deriveKey']
    )
    return subtle.deriveKey(
      { name: 'PBKDF2', hash: kdf.hash, salt: b64ToBytes(saltB64), iterations: kdf.iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    )
  }

  /**
   * Attempt to unlock the bundle with an access code.
   * Returns { slotId, html } on success, or null if no slot accepts the code.
   */
  async function unlock(bundle, code) {
    if (!bundle || bundle.version !== 1 || !bundle.kdf || bundle.kdf.name !== 'PBKDF2') {
      throw new Error('Unsupported bundle format')
    }
    for (var i = 0; i < bundle.slots.length; i++) {
      var slot = bundle.slots[i]
      try {
        var kek = await deriveKek(code, slot.salt, bundle.kdf)
        var rawContentKey = await subtle.decrypt(
          { name: 'AES-GCM', iv: b64ToBytes(slot.iv) },
          kek,
          b64ToBytes(slot.wrapped)
        )
        var contentKey = await subtle.importKey('raw', rawContentKey, 'AES-GCM', false, ['decrypt'])
        var plain = await subtle.decrypt(
          { name: 'AES-GCM', iv: b64ToBytes(bundle.payload.iv) },
          contentKey,
          b64ToBytes(bundle.payload.ciphertext)
        )
        return { slotId: slot.id, html: new TextDecoder().decode(plain) }
      } catch (e) {
        // Wrong code for this slot (GCM auth failure) — try the next one.
      }
    }
    return null
  }

  return { unlock: unlock, normalizeCode: normalizeCode }
})()

// --- Node (test/tooling) export -------------------------------------------
if (typeof module !== 'undefined' && module.exports) {
  module.exports = BastionGate
}

// --- Browser UI -------------------------------------------------------------
if (typeof document !== 'undefined') {
  ;(function () {
    // Deliberately NOT a <form>: with no native submission there is no
    // possible fallback that serialises the access code into the URL.
    var input = document.getElementById('gate-code')
    if (!input) return

    var button = document.getElementById('gate-submit')
    var status = document.getElementById('gate-status')
    var gateCard = document.getElementById('gate')
    var vault = document.getElementById('vault')
    var failures = 0
    var busy = false

    function setStatus(msg, isError) {
      status.textContent = msg
      status.className = isError ? 'gate-status error' : 'gate-status'
    }

    if (!window.isSecureContext || !globalThis.crypto || !globalThis.crypto.subtle) {
      setStatus('This gate requires a secure (HTTPS) context.', true)
      button.disabled = true
      return
    }

    async function attemptUnlock() {
      if (busy) return
      busy = true
      var code = input.value
      if (!BastionGate.normalizeCode(code)) {
        setStatus('Enter your partner access code.', true)
        busy = false
        return
      }
      button.disabled = true
      input.disabled = true
      setStatus('Verifying…', false)
      try {
        var res = await fetch('partner-content.json', { cache: 'no-store' })
        if (!res.ok) throw new Error('Could not load the sealed bundle (' + res.status + ')')
        var bundle = await res.json()
        var result = await BastionGate.unlock(bundle, code)
        if (result) {
          // Decrypted content is authored and sealed by CIPP maintainers — it
          // is trusted first-party content, not user input. Scripts inside it
          // will NOT execute (innerHTML never runs <script>, and CSP has no
          // inline-script allowance anyway).
          vault.innerHTML = result.html
          vault.hidden = false
          gateCard.hidden = true
          document.getElementById('gate-slot').textContent = result.slotId
          document.getElementById('gate-banner').hidden = false
        } else {
          failures++
          // Cosmetic friction only — the real brute-force resistance is the
          // access-code entropy + PBKDF2 cost (see docs/README.md).
          await new Promise(function (r) {
            setTimeout(r, Math.min(failures, 5) * 800)
          })
          setStatus('Access code not recognised. Check the code issued to your organisation.', true)
        }
      } catch (err) {
        setStatus('Unlock failed: ' + err.message, true)
      } finally {
        busy = false
        button.disabled = false
        input.disabled = false
        if (!gateCard.hidden) input.focus()
      }
    }

    button.addEventListener('click', attemptUnlock)
    input.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') {
        ev.preventDefault()
        attemptUnlock()
      }
    })
  })()
}
