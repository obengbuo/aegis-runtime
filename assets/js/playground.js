/* Aegis policy playground.
   A line-for-line port of aegis/policy.py evaluate() (v0.2.0 + the rule-7
   value-classification fix on main). Runs entirely in the browser: nothing
   typed here is sent anywhere. Requires js-yaml (loaded by the page). */
(function () {
  'use strict';

  /* ------------------------------------------------------------------ */
  /* Python-compatible helpers                                           */
  /* ------------------------------------------------------------------ */

  // str(value) for the scalar types JSON can carry.
  function pyStr(v) {
    if (v === null) return 'None';
    if (v === true) return 'True';
    if (v === false) return 'False';
    return String(v);
  }
  // repr() for a str — single quotes, as Python renders it in reason strings.
  function pyRepr(s) {
    s = String(s);
    if (s.indexOf("'") !== -1 && s.indexOf('"') === -1) return '"' + s + '"';
    return "'" + s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n') + "'";
  }
  function isScalar(v) { return v === null || ['string', 'number', 'boolean'].indexOf(typeof v) !== -1; }
  function pyType(v) {
    if (Array.isArray(v)) return 'list';
    if (v === null) return 'NoneType';
    if (typeof v === 'object') return 'dict';
    return { string: 'str', number: Number.isInteger(v) ? 'int' : 'float', boolean: 'bool' }[typeof v];
  }
  // _classify_arg_value: scalar | collection (of scalars, one level) | unsupported
  function classify(v) {
    if (isScalar(v)) return 'scalar';
    if (Array.isArray(v)) return v.every(isScalar) ? 'collection' : 'unsupported';
    return 'unsupported';
  }
  function isMap(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }

  /* ------------------------------------------------------------------ */
  /* Spec validation — mirrors the Pydantic models in policy.py          */
  /* ------------------------------------------------------------------ */
  function validateSpec(data) {
    var errs = [];
    if (!isMap(data)) { return { errors: ['spec must be a YAML mapping, got ' + pyType(data)] }; }
    if (typeof data.task !== 'string') errs.push('task: Field required (string)');
    var dao = data.deny_all_others === undefined ? true : data.deny_all_others;
    if (typeof dao !== 'boolean') errs.push('deny_all_others: Input should be a valid boolean');
    else if (dao === false && typeof data.task === 'string' && data.task.toLowerCase().indexOf('deny_all_others=false') === -1)
      errs.push("deny_all_others is false, but task does not contain 'deny_all_others=false' (case-insensitive). " +
        'Weak posture has to be acknowledged in the task text.');
    if (!isMap(data.servers)) errs.push('servers: Field required (mapping of server name to tools)');
    var servers = {};
    if (isMap(data.servers)) {
      Object.keys(data.servers).forEach(function (sname) {
        var s = data.servers[sname];
        if (!isMap(s) || !isMap(s.tools)) { errs.push('servers.' + sname + '.tools: Field required (mapping)'); return; }
        var tools = {};
        Object.keys(s.tools).forEach(function (tname) {
          var t = s.tools[tname];
          var loc = 'servers.' + sname + '.tools.' + tname;
          if (t === null || t === undefined) { tools[tname] = null; return; }
          if (!isMap(t)) { errs.push(loc + ': Input should be a mapping or null'); return; }
          if (t.args === null || t.args === undefined) { tools[tname] = { args: null }; return; }
          if (!isMap(t.args)) { errs.push(loc + '.args: Input should be a mapping or null'); return; }
          var args = {};
          Object.keys(t.args).forEach(function (aname) {
            var a = t.args[aname];
            var aloc = loc + '.args.' + aname;
            if (a === null || a === undefined) { args[aname] = null; return; }
            if (!isMap(a)) { errs.push(aloc + ': Input should be a mapping or null'); return; }
            var mm = a.must_match_one_of === undefined ? null : a.must_match_one_of;
            var any = a.allow_any === undefined ? false : a.allow_any;
            if (mm !== null) {
              if (!Array.isArray(mm)) errs.push(aloc + '.must_match_one_of: Input should be a valid list');
              else if (mm.length === 0) errs.push(aloc + '.must_match_one_of: must_match_one_of cannot be an empty list');
              else if (!mm.every(function (x) { return typeof x === 'string'; }))
                errs.push(aloc + '.must_match_one_of: every entry must be a string (quote numbers and booleans)');
            }
            if (typeof any !== 'boolean') errs.push(aloc + '.allow_any: Input should be a valid boolean');
            if (any === true && mm !== null)
              errs.push(aloc + ': allow_any and must_match_one_of are mutually exclusive');
            args[aname] = { must_match_one_of: mm, allow_any: any === true };
          });
          tools[tname] = { args: args };
        });
        servers[sname] = { tools: tools };
      });
    }
    var intercepts = [];
    if (data.intercepts !== undefined && data.intercepts !== null) {
      if (!Array.isArray(data.intercepts)) errs.push('intercepts: Input should be a valid list');
      else data.intercepts.forEach(function (r, i) {
        if (!isMap(r) || typeof r.server !== 'string' || typeof r.tool !== 'string')
          errs.push('intercepts.' + i + ': needs string fields server and tool');
        else intercepts.push({ server: r.server, tool: r.tool });
      });
    }
    if (errs.length) return { errors: errs };
    return { spec: { task: data.task, deny_all_others: dao, servers: servers, intercepts: intercepts } };
  }

  /* ------------------------------------------------------------------ */
  /* evaluate() — the hot path. Returns the decision plus a rule trace.  */
  /* ------------------------------------------------------------------ */
  function D(verdict, reason, rule) { return { verdict: verdict, reason: reason, matched_rule: rule }; }

  function evaluateRules(spec, server, tool, args, trace) {
    // Rule 1
    if (!Object.prototype.hasOwnProperty.call(spec.servers, server)) {
      if (spec.deny_all_others) {
        trace.push([1, 'Server listed', 'fail']);
        return D('DENY', "server '" + server + "' not in capability spec", 'rule-1-server-not-listed');
      }
      trace.push([1, 'Server listed', 'bypass']);
      return D('ALLOW', 'all checks passed', 'rule-1-bypassed-weak-posture');
    }
    trace.push([1, 'Server listed', 'pass']);
    var serverSpec = spec.servers[server];

    // Rule 2
    if (!Object.prototype.hasOwnProperty.call(serverSpec.tools, tool)) {
      if (spec.deny_all_others) {
        trace.push([2, 'Tool listed', 'fail']);
        return D('DENY', "tool '" + tool + "' not in capability spec for server '" + server + "'", 'rule-2-tool-not-listed');
      }
      trace.push([2, 'Tool listed', 'bypass']);
      return D('ALLOW', 'all checks passed', 'rule-2-bypassed-weak-posture');
    }
    trace.push([2, 'Tool listed', 'pass']);

    var entry = serverSpec.tools[tool];
    var argsSpec = entry ? entry.args : null;
    var callNames = Object.keys(args);

    // Rules 3 & 4
    if (argsSpec === null) {
      if (callNames.length) {
        trace.push([3, 'Zero-arg tool called with no args', 'fail']);
        return D('DENY', "tool '" + tool + "' declared zero-arg but call supplied args: [" +
          callNames.slice().sort().map(pyRepr).join(', ') + ']', 'rule-3-zero-arg-violation');
      }
      trace.push([3, 'Zero-arg tool called with no args', 'pass']);
      trace.push([4, 'Zero-arg call allowed', 'pass']);
      return D('ALLOW', 'all checks passed', null);
    }
    trace.push([3, 'Args block present', 'pass']);

    // Rule 5
    var specNames = Object.keys(argsSpec);
    for (var i = 0; i < specNames.length; i++) {
      if (!Object.prototype.hasOwnProperty.call(args, specNames[i])) {
        trace.push([5, 'Every spec arg present', 'fail']);
        return D('DENY', 'required arg ' + pyRepr(specNames[i]) + ' missing from call', 'rule-5-missing-required-arg');
      }
    }
    trace.push([5, 'Every spec arg present', 'pass']);

    // Rule 6
    for (var j = 0; j < callNames.length; j++) {
      if (!Object.prototype.hasOwnProperty.call(argsSpec, callNames[j])) {
        trace.push([6, 'No unlisted args', 'fail']);
        return D('DENY', 'arg ' + pyRepr(callNames[j]) + ' not in capability spec', 'rule-6-extra-arg');
      }
    }
    trace.push([6, 'No unlisted args', 'pass']);

    // Rule 7
    var bypassed = false;
    for (var k = 0; k < specNames.length; k++) {
      var name = specNames[k];
      var value = args[name];
      var aEntry = argsSpec[name];
      if (aEntry && aEntry.allow_any) { bypassed = true; continue; }
      var allow = aEntry ? aEntry.must_match_one_of : null;
      var kind = classify(value);
      if (kind === 'unsupported') {
        trace.push([7, 'Argument values', 'fail']);
        return D('DENY', 'arg ' + pyRepr(name) + ' has type ' + pyRepr(pyType(value)) +
          ', which a capability spec cannot express a literal constraint for; set allow_any on this arg to permit it explicitly',
          'rule-7-unsupported-arg-type');
      }
      if (kind === 'collection') {
        if (allow === null) {
          trace.push([7, 'Argument values', 'fail']);
          return D('DENY', 'arg ' + pyRepr(name) + ' is a collection with no must_match_one_of; leaving it unconstrained would permit any value. List the permitted elements, or set allow_any to say so explicitly',
            'rule-7-unconstrained-collection');
        }
        if (value.length === 0) {
          trace.push([7, 'Argument values', 'fail']);
          return D('DENY', 'arg ' + pyRepr(name) + " is an empty collection; it matches nothing in the capability spec, and some tools read an empty collection as 'all'",
            'rule-7-empty-collection');
        }
        for (var e = 0; e < value.length; e++) {
          if (allow.indexOf(pyStr(value[e])) === -1) {
            trace.push([7, 'Argument values', 'fail']);
            return D('DENY', 'arg ' + pyRepr(name) + ' element ' + pyRepr(pyStr(value[e])) + ' not in capability spec',
              'rule-7-value-not-allowed');
          }
        }
        continue;
      }
      if (allow !== null && allow.indexOf(pyStr(value)) === -1) {
        trace.push([7, 'Argument values', 'fail']);
        return D('DENY', 'arg ' + pyRepr(name) + ' value ' + pyRepr(pyStr(value)) + ' not in capability spec',
          'rule-7-value-not-allowed');
      }
    }
    trace.push([7, 'Argument values', bypassed ? 'bypass' : 'pass']);
    trace.push([8, 'All checks passed', 'pass']);
    if (bypassed) return D('ALLOW', 'all checks passed', 'rule-7-bypassed-allow-any');
    return D('ALLOW', 'all checks passed', null);
  }

  function evaluate(spec, server, tool, args) {
    var trace = [];
    var d = evaluateRules(spec, server, tool, args, trace);
    if (d.verdict !== 'ALLOW') { trace.push([9, 'Intercept overlay', 'skip']); return { decision: d, trace: trace }; }
    for (var i = 0; i < spec.intercepts.length; i++) {
      var r = spec.intercepts[i];
      if (r.server === server && r.tool === tool) {
        trace.push([9, 'Intercept overlay', 'hold']);
        return {
          decision: D('INTERCEPT', "call to '" + server + '.' + tool + "' requires operator approval per capability spec", 'rule-9-intercept-required'),
          trace: trace
        };
      }
    }
    trace.push([9, 'Intercept overlay', 'pass']);
    return { decision: d, trace: trace };
  }

  /* ------------------------------------------------------------------ */
  /* Scenarios                                                            */
  /* ------------------------------------------------------------------ */
  var SANDBOX_SPEC = [
    'task: "summarise three meeting files"',
    'deny_all_others: true',
    '',
    'servers:',
    '  filesystem:',
    '    tools:',
    '      read_text_file:',
    '        args:',
    '          path:',
    '            must_match_one_of:',
    '              - /sandbox/meeting-notes.txt',
    '              - /sandbox/agenda.txt',
    '              - /sandbox/action-items.txt',
    '      read_multiple_files:',
    '        args:',
    '          paths:',
    '            must_match_one_of:',
    '              - /sandbox/meeting-notes.txt',
    '              - /sandbox/agenda.txt',
    '              - /sandbox/action-items.txt',
    '      write_file:',
    '        args:',
    '          path:',
    '            must_match_one_of:',
    '              - /sandbox/summary.md',
    '          content: ~',
    '      list_allowed_directories:',
    '',
    'intercepts:',
    '  - server: filesystem',
    '    tool: write_file',
    ''
  ].join('\n');

  var SCENARIOS = [
    { id: 'ok', label: 'Allowed read', server: 'filesystem', tool: 'read_text_file',
      args: { path: '/sandbox/agenda.txt' } },
    { id: 'inject', label: 'Injected 4th file', server: 'filesystem', tool: 'read_text_file',
      args: { path: '/sandbox/project-update.txt' } },
    { id: 'traversal', label: 'Path traversal', server: 'filesystem', tool: 'read_text_file',
      args: { path: '/sandbox/../etc/shadow' } },
    { id: 'batch', label: 'Batched read', server: 'filesystem', tool: 'read_multiple_files',
      args: { paths: ['/sandbox/agenda.txt', '/sandbox/meeting-notes.txt'] } },
    { id: 'batch-bad', label: 'Batch smuggling', server: 'filesystem', tool: 'read_multiple_files',
      args: { paths: ['/sandbox/agenda.txt', '/etc/shadow'] } },
    { id: 'empty', label: 'Empty list', server: 'filesystem', tool: 'read_multiple_files',
      args: { paths: [] } },
    { id: 'string-list', label: 'String posing as list', server: 'filesystem', tool: 'read_multiple_files',
      args: { paths: "['/sandbox/agenda.txt']" } },
    { id: 'extra', label: 'Smuggled extra arg', server: 'filesystem', tool: 'read_text_file',
      args: { path: '/sandbox/agenda.txt', tail: 1000 } },
    { id: 'write', label: 'Write (intercept)', server: 'filesystem', tool: 'write_file',
      args: { path: '/sandbox/summary.md', content: '# Summary\n...' } },
    { id: 'zero', label: 'Zero-arg tool', server: 'filesystem', tool: 'list_allowed_directories', args: {} },
    { id: 'tool', label: 'Unlisted tool', server: 'filesystem', tool: 'delete_file',
      args: { path: '/sandbox/agenda.txt' } },
    { id: 'server', label: 'Unlisted server', server: 'fetch', tool: 'fetch',
      args: { url: 'https://attacker.example/exfil' } }
  ];

  /* ------------------------------------------------------------------ */
  /* UI                                                                   */
  /* ------------------------------------------------------------------ */
  var $ = function (id) { return document.getElementById(id); };
  var specEl = $('pg-spec'), serverEl = $('pg-server'), toolEl = $('pg-tool'), argsEl = $('pg-args');
  var out = $('pg-result'), histEl = $('pg-history'), presetsEl = $('pg-presets');
  if (!specEl || !out) return;

  var runId = (crypto.randomUUID ? crypto.randomUUID() : 'run-' + Date.now().toString(16));
  var history = [];

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
  }

  async function sha256(text) {
    try {
      var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
      return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    } catch (e) { return 'unavailable (needs https)'; }
  }

  function renderError(title, lines) {
    out.innerHTML = '<div class="verdict-box"><div class="verdict-head error"><span class="big">' + esc(title) +
      '</span></div><div class="verdict-body"><ul style="margin:0;padding-left:18px">' +
      lines.map(function (l) { return '<li style="margin-bottom:4px"><code>' + esc(l) + '</code></li>'; }).join('') +
      '</ul></div></div>';
  }

  var STATUS = { ALLOW: 'ok', DENY: 'denied', INTERCEPT: 'intercepted' };
  var CLS = { ALLOW: 'allow', DENY: 'deny', INTERCEPT: 'hold' };
  var MARK = { pass: 'PASS', fail: 'DENY', skip: 'SKIP', bypass: 'WAIVED', hold: 'HOLD' };
  var MARKCLS = { pass: 'pass', fail: 'fail', skip: 'skip', bypass: 'hold', hold: 'hold' };

  async function run(record) {
    var yamlText = specEl.value;
    var data;
    try { data = window.jsyaml.load(yamlText); }
    catch (e) { renderError('SpecValidationError', ['spec YAML parse error: ' + e.message.split('\n')[0]]); return; }
    var v = validateSpec(data);
    if (v.errors) { renderError('SpecValidationError', v.errors); return; }

    var args;
    try { args = argsEl.value.trim() ? JSON.parse(argsEl.value) : {}; }
    catch (e) { renderError('Invalid call arguments', ['args must be a JSON object: ' + e.message]); return; }
    if (!isMap(args)) { renderError('Invalid call arguments', ['args must be a JSON object, e.g. {"path": "/sandbox/agenda.txt"}']); return; }

    var server = serverEl.value.trim(), tool = toolEl.value.trim();
    var t0 = performance.now();
    var res = evaluate(v.spec, server, tool, args);
    var micros = Math.max(1, Math.round((performance.now() - t0) * 1000));
    var d = res.decision;
    var hash = await sha256(yamlText);

    var traceHtml = res.trace.map(function (t) {
      return '<li class="' + (t[2] === 'skip' ? 'skipped' : '') + '"><span class="ix">' + t[0] + '</span><span>' + esc(t[1]) +
        '</span><span class="st ' + MARKCLS[t[2]] + '">' + MARK[t[2]] + '</span></li>';
    }).join('');

    var weak = d.matched_rule && d.matched_rule.indexOf('bypassed') !== -1;
    out.innerHTML =
      '<div class="verdict-box" role="status" aria-live="polite">' +
        '<div class="verdict-head ' + CLS[d.verdict] + '"><span class="big">' + d.verdict + '</span>' +
        '<span class="muted mono" style="font-size:12.5px;margin-left:auto">evaluated in ~' + micros + ' µs, in your browser</span></div>' +
        '<div class="verdict-body"><dl>' +
          '<dt>matched_rule</dt><dd>' + (d.matched_rule ? esc(d.matched_rule) : '<span class="muted">null — a clean pass</span>') + '</dd>' +
          '<dt>reason</dt><dd>' + esc(d.reason) + '</dd>' +
          '<dt>reaches server</dt><dd>' + (d.verdict === 'ALLOW' ? 'yes' : d.verdict === 'INTERCEPT' ? 'only if the approval callback returns True' : 'no — the MCP server never sees this call') + '</dd>' +
        '</dl>' +
        (weak ? '<p class="mt-24" style="margin-bottom:0;font-size:14px;color:var(--hold)">Allowed, but only because a check was waived. The audit record carries this rule id so the waiver can be found with a query, instead of looking like an ordinary pass.</p>' : '') +
        '</div>' +
        '<ol class="trace" aria-label="Rule trace">' + traceHtml + '</ol>' +
      '</div>';

    if (record) {
      var rec = {
        call_id: (crypto.randomUUID ? crypto.randomUUID() : String(Date.now())),
        ts: new Date().toISOString(),
        run_id: runId,
        status: STATUS[d.verdict],
        server: server, tool: tool, args: args
      };
      if (d.verdict !== 'ALLOW') { rec.reason = d.reason; rec.matched_rule = d.matched_rule; }
      else if (d.matched_rule) rec.matched_rule = d.matched_rule;
      rec.spec_hash = hash;
      history.unshift(rec);
      if (history.length > 25) history.pop();
      renderHistory();
    }
  }

  function renderHistory() {
    if (!history.length) { histEl.innerHTML = '<div class="empty">Run a call to see the audit record Aegis would write.</div>'; return; }
    histEl.innerHTML = '<pre>' + history.map(function (r) { return esc(JSON.stringify(r)); }).join('\n') + '</pre>';
  }

  function loadScenario(s) {
    serverEl.value = s.server;
    toolEl.value = s.tool;
    argsEl.value = JSON.stringify(s.args, null, 2);
    presetsEl.querySelectorAll('.chip').forEach(function (c) { c.setAttribute('aria-pressed', c.dataset.id === s.id ? 'true' : 'false'); });
    run(true);
  }

  SCENARIOS.forEach(function (s) {
    var b = document.createElement('button');
    b.type = 'button'; b.className = 'chip'; b.textContent = s.label; b.dataset.id = s.id;
    b.setAttribute('aria-pressed', 'false');
    b.addEventListener('click', function () { loadScenario(s); });
    presetsEl.appendChild(b);
  });

  specEl.value = SANDBOX_SPEC;
  $('pg-run').addEventListener('click', function () { run(true); });
  $('pg-reset').addEventListener('click', function () { specEl.value = SANDBOX_SPEC; run(false); });
  $('pg-clear').addEventListener('click', function () { history = []; renderHistory(); });
  [serverEl, toolEl, argsEl, specEl].forEach(function (el) {
    el.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); run(true); }
    });
  });
  var debounce;
  [serverEl, toolEl, argsEl, specEl].forEach(function (el) {
    el.addEventListener('input', function () {
      presetsEl.querySelectorAll('.chip').forEach(function (c) { c.setAttribute('aria-pressed', 'false'); });
      clearTimeout(debounce); debounce = setTimeout(function () { run(false); }, 250);
    });
  });

  renderHistory();
  loadScenario(SCENARIOS[1]);

  // Expose for the self-test on the page and for curious readers in devtools.
  window.aegisPlayground = { evaluate: evaluate, validateSpec: validateSpec };
})();
