// Ghost Gate demo client.
//
// Talks only to the local bridge, on its own origin. The privacy property this page exists to show is
// structural rather than a promise: there is no code here that requests, stores or displays a balance,
// a key, a mask or a UTXO identifier, because the API has no route that returns one and no field in a
// proof request that would ask for one.

'use strict';

const $ = (id) => document.getElementById(id);

/** The gate this page is demonstrating. Set by the bridge, or overridden with ?gate=. */
const GATE_ID = new URLSearchParams(location.search).get('gate') || 'g1';

/**
 * Formats a raw amount with a resource's divisibility.
 *
 * Integer arithmetic only, deliberately: this is the same rule consensus applies (`raw >= threshold`)
 * with decimal places added for a human. It is duplicated here rather than shared because a page must
 * not be able to influence the bridge's comparison, and a display bug must never be able to move a
 * threshold.
 */
function formatAmount(raw, divisibility) {
  const places = Math.min(Number(divisibility) || 0, 18);
  const digits = String(raw);
  if (places === 0) return digits;
  const padded = digits.padStart(places + 1, '0');
  const whole = padded.slice(0, padded.length - places).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return `${whole}.${padded.slice(padded.length - places)}`;
}

/** Thin wrapper so every call site is one line and failures land in one place. */
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    cache: 'no-store',
  });
  const text = await response.text();
  let body = {};
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { error: text };
  }
  return { status: response.status, ok: response.ok, body };
}

async function refreshGate() {
  const { body } = await api(`/gate/${GATE_ID}`);
  if (!body.gate_id) {
    $('asset-symbol').textContent = 'unknown gate';
    $('threshold').textContent = '—';
    return;
  }
  $('asset-symbol').textContent = body.symbol || 'unlabelled asset';
  $('asset-address').textContent = body.resource_address;
  // The threshold is rendered from the raw integer and the divisibility the *gate* reported.
  $('threshold').textContent = `≥ ${formatAmount(body.threshold, body.divisibility)} ${body.symbol || ''}`.trim();
  $('divisibility').textContent = String(body.divisibility);
}

async function refreshWallet() {
  const { status, body } = await api('/wallet/status');
  if (status === 200 && body.reachable) {
    $('wallet-line').textContent =
      `Wallet connected — ${body.network_name || 'network unknown'}. ` +
      'Your balance is not requested and is not available to this page.';
    $('connect').disabled = true;
    $('connect-title').textContent = 'Wallet connected';
    $('connect').hidden = true;
    // A reachable wallet is the moment to offer the action, and to say plainly what will be revealed.
    $('progress').hidden = false;
    markStep('statement');
    document.getElementById('progress').querySelector('h2').textContent = 'Ready';
    renderStepLabels();
    addProveButton();
  } else {
    $('wallet-line').textContent =
      'No wallet daemon reachable. Start walletd, then connect again.';
    $('connect').disabled = false;
  }
}

function renderStepLabels() {
  const labels = {
    statement: 'Building the private statement',
    approval: 'Awaiting wallet approval',
    submitting: 'Submitting',
    waiting: 'Waiting for commitment',
  };
  document.querySelectorAll('#steps li').forEach((li) => {
    li.textContent = labels[li.dataset.step];
  });
}

function markStep(name) {
  const order = ['statement', 'approval', 'submitting', 'waiting'];
  const index = order.indexOf(name);
  document.querySelectorAll('#steps li').forEach((li) => {
    const i = order.indexOf(li.dataset.step);
    li.classList.toggle('done', i < index);
    li.classList.toggle('active', i === index);
  });
}

function completeSteps() {
  document.querySelectorAll('#steps li').forEach((li) => {
    li.classList.remove('active');
    li.classList.add('done');
  });
}

function resetSteps() {
  document.querySelectorAll('#steps li').forEach((li) => li.classList.remove('done', 'active'));
  markStep('statement');
}

function addProveButton() {
  if ($('prove')) return;
  const button = document.createElement('button');
  button.id = 'prove';
  button.className = 'primary';
  button.textContent = 'Prove Access';
  button.addEventListener('click', prove);
  $('connect').appendChild(button);
}

function showOutcome(kind, title, body, detail = {}) {
  const panel = $('outcome');
  panel.hidden = false;
  panel.classList.remove('granted', 'denied');
  panel.classList.add(kind);
  $('outcome-title').textContent = title;
  $('outcome-title').className = kind === 'granted' ? 'granted' : '';
  $('outcome-body').textContent = body;

  const dl = $('outcome-detail');
  dl.innerHTML = '';
  for (const [label, value] of Object.entries(detail)) {
    if (value === undefined || value === null || value === '') continue;
    const dt = document.createElement('dt');
    dt.textContent = label;
    const dd = document.createElement('dd');
    if (label.toLowerCase().includes('resource') || label.toLowerCase().includes('nonce')) {
      const code = document.createElement('code');
      code.textContent = value;
      dd.appendChild(code);
    } else {
      dd.textContent = value;
    }
    dl.append(dt, dd);
  }
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function prove() {
  $('prove').disabled = true;
  $('outcome').hidden = true;
  resetSteps();
  markStep('statement');

  // 1. A fresh, single-use challenge from the bridge, with a session commitment the browser does not
  //    get to choose. Nothing here is spent yet.
  const challenge = await api(`/gate/${GATE_ID}/challenge`, { method: 'POST', body: '{}' });
  if (!challenge.ok) {
    $('prove').disabled = false;
    showOutcome('denied', 'ACCESS DENIED', challenge.body.error || 'no challenge could be issued.');
    return;
  }
  const { challenge_nonce, session_commitment } = challenge.body;

  // 2. Ask for the proof. The request names a gate and a nonce — nothing else. There is nowhere in it
  //    to put an amount, a destination or a UTXO, so there is nothing for this page to get wrong.
  markStep('approval');
  const asked = await api(`/gate/${GATE_ID}/prove`, {
    method: 'POST',
    body: JSON.stringify({ gate_id: GATE_ID, challenge_nonce, session_commitment }),
  });

  // A 409 is the bridge refusing before it touched the wallet: a stale or spent challenge, or one
  // belonging to a different session. Replay lands here.
  if (asked.status === 409) {
    $('prove').disabled = false;
    resetSteps();
    const reason = asked.body.refused || '';
    if (/already been answered/.test(reason)) {
      showOutcome(
        'denied',
        'ACCESS DENIED',
        'Challenge already used. Request a fresh challenge.',
      );
    } else if (/expired/.test(reason)) {
      showOutcome('denied', 'ACCESS DENIED', 'Challenge expired. Request a fresh challenge.');
    } else {
      showOutcome('denied', 'ACCESS DENIED', 'The threshold was not proven. Your exact balance remains private.');
    }
    return;
  }
  if (!asked.ok || !asked.body.proof_id) {
    $('prove').disabled = false;
    showOutcome('denied', 'ACCESS DENIED', asked.body.error || 'the proof could not be started.');
    return;
  }

  markStep('submitting');
  // 3. Poll until the network has committed or refused. Polling a job id, not holding a transaction.
  const terminal = await poll(asked.body.proof_id);
  $('prove').disabled = false;

  if (terminal.state === 'accepted') {
    completeSteps();
    const r = terminal.result;
    showOutcome(
      'granted',
      '👻 ACCESS GRANTED',
      'Minimum threshold proven. Actual balance not disclosed. Challenge consumed.',
      {
        Gate: r.gate_id,
        Resource: r.resource_address,
        'Attested minimum': `${formatAmount(r.attested_minimum, currentDivisibility())} ${currentSymbol()}`,
        'Required': `${formatAmount(r.required_minimum, currentDivisibility())} ${currentSymbol()}`,
        'Live inputs': r.input_count,
        'Challenge nonce': r.challenge_nonce,
        Transaction: r.transaction_id,
      },
    );
    return;
  }

  resetSteps();
  if (terminal.state === 'refused') {
    const reason = terminal.reason || '';
    if (/already been used/.test(reason)) {
      showOutcome('denied', 'ACCESS DENIED', 'Challenge already used. Request a fresh challenge.');
      return;
    }
    showOutcome(
      'denied',
      'ACCESS DENIED',
      'The required threshold was not proven. Your exact balance remains private.',
      { Reason: reason },
    );
    return;
  }
  showOutcome(
    'denied',
    'ACCESS DENIED',
    'The proof could not be completed. Your exact balance remains private.',
    { Reason: terminal.reason || 'unknown' },
  );
}

/** Polls a proof job until the network has committed a verdict. */
async function poll(proofId, attempt = 0) {
  if (attempt > 60) return { state: 'failed', reason: 'timed out waiting for the network' };
  const { body } = await api(`/proof/${proofId}/status`);
  if (body.state === 'accepted' || body.state === 'refused' || body.state === 'failed') return body;
  await new Promise((resolve) => setTimeout(resolve, 1500));
  return poll(proofId, attempt + 1);
}

let cachedGate = null;
function currentDivisibility() {
  return cachedGate ? cachedGate.divisibility : 0;
}
function currentSymbol() {
  return cachedGate ? cachedGate.symbol : '';
}

$('connect').addEventListener('click', refreshWallet);
$('again').addEventListener('click', async () => {
  $('outcome').hidden = true;
  resetSteps();
  await refreshGate();
  await refreshWallet();
});

$('create-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const body = {
    resource_address: $('c-resource').value.trim(),
    symbol: $('c-symbol').value.trim(),
    threshold: Number($('c-threshold').value),
    divisibility: Number($('c-divisibility').value),
    relying_site: $('c-site').value.trim(),
    session_secs: Number($('c-session').value),
  };
  // Shown rather than sent. Creating a gate is a chain transaction and an operator decision; this page
  // does not have a wallet connection that could authorise one, and pretending otherwise would be the
  // most dishonest thing it could do.
  const pre = $('c-output');
  pre.hidden = false;
  pre.textContent =
    'Gate specification\n' +
    '------------------\n' +
    `resource address : ${body.resource_address}\n` +
    `threshold        : ${body.threshold} raw units\n` +
    `renders as       : ≥ ${formatAmount(body.threshold, body.divisibility)} ${body.symbol || ''}\n` +
    `divisibility     : ${body.divisibility} (display only)\n` +
    `relying site     : ${body.relying_site}\n` +
    `session duration : ${body.session_secs}s\n\n` +
    'The resource address is what the gate binds to. The symbol is display only and is never checked\n' +
    'against anything. Publishing this gate is a chain transaction; the bridge did not submit one.';
});

(async function start() {
  const health = await api('/health');
  $('version').textContent = health.body.version || 'unknown';
  const gate = await api(`/gate/${GATE_ID}`);
  cachedGate = gate.body.gate_id ? gate.body : null;
  await refreshGate();
  await refreshWallet();
})();