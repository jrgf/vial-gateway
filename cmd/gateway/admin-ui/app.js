
(function () {
  'use strict';

  var csrf = document.body.dataset.csrf || '';
  var model = { active: '', routes: [], editorVersion: 0, routeBaseVersion: '', routeDraft: null, ddnsBaseVersion: '', auditCursors: [''], auditPage: 0 };
  var noticeTimer;
  var $ = function (id) { return document.getElementById(id); };

  function make(tag, className, value) {
    var item = document.createElement(tag);
    if (className) item.className = className;
    if (value !== undefined) item.textContent = value;
    return item;
  }

  function show(message, failed) {
    var box = $('notice');
    box.textContent = message;
    box.className = failed ? 'notice error' : 'notice';
    box.hidden = false;
    window.clearTimeout(noticeTimer);
    noticeTimer = window.setTimeout(function () { box.hidden = true; }, failed ? 7000 : 3500);
  }

  async function api(path, options) {
    options = options || {};
    var headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (options.body !== undefined) {
      headers.set('Content-Type', 'application/json');
      if (typeof options.body !== 'string') options.body = JSON.stringify(options.body);
    }
    if (csrf && options.method && options.method !== 'GET') headers.set('X-CSRF-Token', csrf);
    options.headers = headers;
    var response = await fetch(path, options);
    var type = response.headers.get('content-type') || '';
    var data = type.indexOf('application/json') >= 0 ? await response.json() : null;
    if (!response.ok) {
      var message = data && data.error && data.error.message ? data.error.message : 'Request failed (' + response.status + ')';
      throw new Error(message);
    }
    return data;
  }

  function statusPill(good, text, warning) {
    var item = make('span', 'status ' + (warning ? 'warn' : good ? 'good' : 'bad'));
    item.append(make('i'), document.createTextNode(text));
    return item;
  }

  function tag(text, className) { return make('span', 'tag' + (className ? ' ' + className : ''), text); }

  function formatDate(value) {
    if (!value) return '—';
    var date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
  }

  function setConnection(ok) {
    var item = $('connection');
    item.className = 'status ' + (ok ? 'good' : 'bad');
    item.replaceChildren(make('i'), document.createTextNode(ok ? 'Control plane online' : 'Control plane unavailable'));
  }

  function renderStatus(data) {
    model.active = String(data.active_version);
    model.routes = data.routes || [];
    $('stat-version').textContent = data.active_version;
    $('stat-routes').textContent = data.route_count;
    $('stat-policies').textContent = data.auth_policy_count + ' auth · ' + data.rate_policy_count + ' rate · ' + data.cache_policy_count + ' cache';
    $('stat-health').textContent = data.healthy_upstreams + ' / ' + data.total_upstreams;
    $('health-summary').textContent = data.total_upstreams && data.healthy_upstreams === data.total_upstreams ? 'All endpoints available' : 'Endpoint attention required';
    $('stat-dns').textContent = data.dynamic_dns_enabled ? 'Enabled' : 'Disabled';
    $('dns-summary').textContent = data.dynamic_dns_enabled ? 'External IP changes are monitored' : 'External IP worker is off';
    $('ddns-state').className = 'status ' + (data.dynamic_dns_enabled ? 'good' : 'waiting');
    $('ddns-state').replaceChildren(make('i'), document.createTextNode(data.dynamic_dns_enabled ? 'Worker enabled' : 'Worker disabled'));
    $('ddns-token').textContent = data.dynamic_dns_bearer_configured ? 'Provider bearer token configured' : 'No provider bearer token configured';
    $('service-name').textContent = data.service_name || 'Vial Gateway';
    $('telemetry-summary').textContent = data.tracing_enabled ? 'OTLP trace export enabled' : 'Metrics enabled · tracing disabled';
    $('schema-version').textContent = 'Schema v' + data.schema_version;
    $('route-count').textContent = data.route_count + (data.route_count === 1 ? ' route' : ' routes');
    $('last-updated').textContent = 'Updated ' + new Intl.DateTimeFormat(undefined, { timeStyle: 'medium' }).format(new Date());
    renderRoutes(model.routes);
    renderCacheRoutes(model.routes);
  }

  function formatMetric(value, suffix) {
    var number = Number(value);
    if (!Number.isFinite(number)) return '—';
    return number.toLocaleString(undefined, { minimumFractionDigits: number > 0 && number < 1 ? 2 : 0, maximumFractionDigits: 2 }) + (suffix || '');
  }

  function renderStatistics(data) {
    $('metric-rps').textContent = formatMetric(data.requests_per_second);
    $('metric-errors').textContent = formatMetric(data.error_rate_percent, '%');
    $('metric-upstream').textContent = formatMetric(data.upstream_failures_per_second);
    $('metric-cache').textContent = formatMetric(data.cache_hit_rate_percent, '%');
    $('metrics-state').className = 'status good';
    $('metrics-state').replaceChildren(make('i'), document.createTextNode('Prometheus · ' + data.window));
    var body = $('metric-routes');
    body.replaceChildren();
    if (!data.routes || !data.routes.length) {
      var emptyRow = make('tr');
      var emptyCell = make('td', 'empty', 'No route traffic recorded in this window.');
      emptyCell.colSpan = 2;
      emptyRow.append(emptyCell);
      body.append(emptyRow);
      return;
    }
    data.routes.forEach(function (route) {
      var row = make('tr');
      row.append(make('td', '', route.route), make('td', '', formatMetric(route.requests_per_second)));
      body.append(row);
    });
  }

  async function loadStatistics(quiet) {
    try { renderStatistics(await api('/admin/v1/statistics')); }
    catch (error) {
      ['metric-rps', 'metric-errors', 'metric-upstream', 'metric-cache'].forEach(function (id) { $(id).textContent = '—'; });
      $('metrics-state').className = 'status bad';
      $('metrics-state').replaceChildren(make('i'), document.createTextNode('Unavailable'));
      if (!quiet) show(error.message, true);
    }
  }

  function renderRoutes(routes) {
    var body = $('routes-body');
    body.replaceChildren();
    if (!routes.length) {
      var emptyRow = make('tr');
      var emptyCell = make('td', 'empty', 'No routes are configured. Create a configuration version to add one.');
      emptyCell.colSpan = 6;
      emptyRow.append(emptyCell);
      body.append(emptyRow);
      return;
    }
    routes.forEach(function (route) {
      var row = make('tr');
      var routeCell = make('td');
      routeCell.append(make('strong', '', route.name));
      routeCell.append(make('small', '', route.hosts && route.hosts.length ? route.hosts.join(', ') : 'Any host'));
      var match = make('td');
      match.append(make('code', '', (route.methods || []).join(' · ') || 'ANY'));
      match.append(make('small', '', route.path_prefix));
      var policies = make('td');
      var policyStack = make('div', 'policy-stack');
      if (route.auth_policy) policyStack.append(tag('auth: ' + route.auth_policy));
      if (route.rate_policy) policyStack.append(tag('rate: ' + route.rate_policy));
      if (route.cache_policy) policyStack.append(tag('cache: ' + route.cache_policy));
      if (route.streaming) policyStack.append(tag('streaming'));
      if (!policyStack.childElementCount) policyStack.append(tag('public'));
      policies.append(policyStack);
      var upstreams = make('td');
      var list = make('div', 'endpoint-list');
      var endpoints = route.upstreams || [];
      endpoints.forEach(function (endpoint) {
        var endpointNode = make('span', 'endpoint');
        endpointNode.title = endpoint.url + ' · circuit ' + endpoint.breaker;
        endpointNode.append(make('span', 'endpoint-dot' + (endpoint.healthy ? ' good' : '')));
        endpointNode.append(make('code', '', new URL(endpoint.url).host));
        list.append(endpointNode);
      });
      upstreams.append(list);
      var healthy = endpoints.length > 0 && route.healthy_upstreams === endpoints.length;
      var health = make('td');
      health.append(statusPill(healthy, route.healthy_upstreams + '/' + endpoints.length + ' healthy', route.healthy_upstreams > 0 && !healthy));
      var actions = make('td');
      var actionStack = make('div', 'version-actions');
      actionStack.append(button('Edit', 'ghost', function () { openRoute(route.name); }));
      actionStack.append(button('Remove', 'danger', function () { removeRoute(route.name); }));
      actions.append(actionStack);
      row.append(routeCell, match, policies, upstreams, health, actions);
      body.append(row);
    });
  }

  function renderCacheRoutes(routes) {
    var select = $('cache-route');
    var selected = select.value;
    select.replaceChildren(new Option('All routes', ''));
    routes.forEach(function (route) { select.append(new Option(route.name, route.name)); });
    if (Array.from(select.options).some(function (option) { return option.value === selected; })) select.value = selected;
  }

  async function loadStatus(quiet) {
    try {
      renderStatus(await api('/admin/v1/status'));
      setConnection(true);
      if (!quiet) show('Live gateway status refreshed.');
    } catch (error) {
      setConnection(false);
      if (!quiet) show(error.message, true);
    }
  }

  function button(text, className, action) {
    var item = make('button', 'button ' + className, text);
    item.type = 'button';
    item.addEventListener('click', action);
    return item;
  }

  function renderVersions(data) {
    model.active = String(data.active || model.active);
    var list = $('versions');
    list.replaceChildren();
    if (!data.versions || !data.versions.length) {
      list.append(make('p', 'empty', 'No stored configurations.'));
      return;
    }
    data.versions.forEach(function (version) {
      var current = String(version) === model.active;
      var row = make('div', 'version');
      var title = make('div');
      title.append(make('strong', '', 'Version ' + version));
      if (current) title.append(tag('Active', 'active'));
      var actions = make('div', 'version-actions');
      actions.append(button('View', 'ghost', function () { loadConfig(version); }));
      if (!current) {
        actions.append(button(Number(version) < Number(model.active) ? 'Rollback' : 'Activate', 'secondary', function () { activateConfig(version); }));
        actions.append(button('Delete', 'danger', function () { deleteConfig(version); }));
      }
      row.append(title, actions);
      list.append(row);
    });
  }

  async function loadVersions() {
    try { renderVersions(await api('/admin/v1/configs')); }
    catch (error) { show(error.message, true); }
  }

  async function loadConfig(version) {
    try {
      var configuration = await api('/admin/v1/configs/' + encodeURIComponent(version));
      configuration.version = Number(version);
      model.editorVersion = configuration.version;
      $('config-editor').value = JSON.stringify(configuration, null, 2);
      $('editor-title').textContent = 'Configuration version ' + model.editorVersion;
      $('editor-state').textContent = String(model.editorVersion) === model.active ? 'Active' : 'Stored';
      $('editor-state').className = 'tag' + (String(model.editorVersion) === model.active ? ' active' : '');
    } catch (error) { show(error.message, true); }
  }

  function editorJSON() {
    try { return JSON.parse($('config-editor').value); }
    catch (error) { throw new Error('Configuration JSON is invalid: ' + error.message); }
  }

  async function validateConfig() {
    try {
      var result = await api('/admin/v1/configs/validate', { method: 'POST', body: editorJSON() });
      $('editor-state').textContent = 'Valid';
      $('editor-state').className = 'tag active';
      show('Version ' + result.version + ' is valid.');
    } catch (error) {
      $('editor-state').textContent = 'Invalid';
      $('editor-state').className = 'tag revoked';
      show(error.message, true);
    }
  }

  async function saveConfig() {
    try {
      var configuration = editorJSON();
      var result = await api('/admin/v1/configs', { method: 'POST', body: configuration });
      model.editorVersion = Number(result.version);
      show('Configuration version ' + result.version + ' saved. Activate it when ready.');
      await loadVersions();
    } catch (error) { show(error.message, true); }
  }

  async function activateConfig(version) {
    var rollback = Number(version) < Number(model.active);
    if (!window.confirm((rollback ? 'Roll back' : 'Activate') + ' configuration version ' + version + '?')) return;
    try {
      await api('/admin/v1/configs/' + encodeURIComponent(version) + '/' + (rollback ? 'rollback' : 'activate'), { method: 'POST', headers: { 'If-Match': model.active } });
      show('Configuration version ' + version + ' is active.');
      await Promise.all([loadStatus(true), loadVersions(), loadAudit()]);
      await loadConfig(version);
    } catch (error) { show(error.message, true); }
  }

  async function deleteConfig(version) {
    if (!window.confirm('Permanently delete inactive configuration version ' + version + '? This cannot be undone.')) return;
    try {
      await api('/admin/v1/configs/' + encodeURIComponent(version), { method: 'DELETE' });
      show('Configuration version ' + version + ' deleted.');
      await Promise.all([loadVersions(), loadAudit()]);
      if (model.editorVersion === Number(version)) await loadConfig(model.active);
    } catch (error) { show(error.message, true); }
  }

  async function newConfig() {
    try {
      var versions = await api('/admin/v1/configs');
      var active = String(versions.active);
      var configuration = await api('/admin/v1/configs/' + encodeURIComponent(active));
      var allVersions = (versions.versions || []).map(Number);
      configuration.version = Math.max(Number(active), allVersions.length ? Math.max.apply(Math, allVersions) : 0) + 1;
      $('config-editor').value = JSON.stringify(configuration, null, 2);
      model.editorVersion = configuration.version;
      $('editor-title').textContent = 'New configuration version ' + configuration.version;
      $('editor-state').textContent = 'Draft';
      $('editor-state').className = 'tag';
      $('config-editor').focus();
    } catch (error) { show(error.message, true); }
  }

  function splitValues(value) {
    return value.split(/[\s,]+/).map(function (item) { return item.trim(); }).filter(Boolean);
  }

  async function openRoute(name) {
    try {
      var versions = await api('/admin/v1/configs');
      var active = String(versions.active);
      var configuration = await api('/admin/v1/configs/' + encodeURIComponent(active));
      var route = name ? (configuration.routes || []).find(function (item) { return item.name === name; }) : null;
      if (name && !route) throw new Error('Route no longer exists. Refresh and try again.');
      model.routeBaseVersion = active;
      model.routeDraft = route ? JSON.parse(JSON.stringify(route)) : null;
      $('route-form').reset();
      $('route-original-name').value = route ? route.name : '';
      $('route-name').value = route ? route.name : '';
      $('route-path').value = route ? route.path_prefix : '';
      $('route-hosts').value = route && route.hosts ? route.hosts.join(', ') : '';
      $('route-rewrite').value = route ? route.path_rewrite || '' : '';
      $('route-upstreams').value = route && route.upstreams ? route.upstreams.join('\n') : '';
      var common = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
      var methods = route && route.methods ? route.methods.map(function (method) { return method.toUpperCase(); }) : ['GET'];
      document.querySelectorAll('#route-methods input').forEach(function (input) { input.checked = methods.includes(input.value); });
      $('route-custom-methods').value = methods.filter(function (method) { return !common.includes(method); }).join(', ');
      $('route-auth').value = route ? route.auth_policy || '' : '';
      $('route-scopes').value = route && route.scopes ? route.scopes.join(', ') : '';
      $('route-rate').value = route ? route.rate_policy || '' : '';
      $('route-cache').value = route ? route.cache_policy || '' : '';
      $('route-health').value = route ? route.health_path || '' : '';
      $('route-timeout').value = route ? route.timeout || '' : '15s';
      $('route-max-body').value = route ? route.max_body_bytes || '' : '1048576';
      $('route-concurrency').value = route ? route.concurrency || '' : '';
      $('route-retries').value = route ? route.retries || '' : '';
      $('route-redirects').checked = route ? !!route.rewrite_redirects : false;
      $('route-streaming').checked = route ? !!route.streaming : false;
      $('route-dialog-title').textContent = route ? 'Edit route ' + route.name : 'Add route';
      $('save-route').textContent = route ? 'Save & activate' : 'Add & activate';
      $('route-dialog').showModal();
      $('route-name').focus();
    } catch (error) { show(error.message, true); }
  }

  function readRoute() {
    var route = model.routeDraft ? JSON.parse(JSON.stringify(model.routeDraft)) : {};
    var methods = Array.from(document.querySelectorAll('#route-methods input:checked')).map(function (input) { return input.value; });
    methods = methods.concat(splitValues($('route-custom-methods').value).map(function (method) { return method.toUpperCase(); }));
    methods = Array.from(new Set(methods));
    var upstreams = $('route-upstreams').value.split(/\r?\n/).map(function (item) { return item.trim(); }).filter(Boolean);
    if (!methods.length) throw new Error('Select at least one HTTP method.');
    if (!upstreams.length) throw new Error('Add at least one upstream URL.');
    route.name = $('route-name').value.trim();
    route.hosts = $('route-hosts').value.split(',').map(function (item) { return item.trim(); }).filter(Boolean);
    route.methods = methods;
    route.path_prefix = $('route-path').value.trim();
    route.path_rewrite = $('route-rewrite').value.trim();
    route.upstreams = upstreams;
    route.health_path = $('route-health').value.trim();
    route.health_interval = route.health_interval || '10s';
    route.timeout = $('route-timeout').value.trim() || route.timeout || '15s';
    route.max_body_bytes = Number($('route-max-body').value || route.max_body_bytes || 1048576);
    route.auth_policy = $('route-auth').value.trim();
    route.scopes = splitValues($('route-scopes').value);
    route.rate_policy = $('route-rate').value.trim();
    route.concurrency = Number($('route-concurrency').value || 0);
    route.retries = Number($('route-retries').value || 0);
    route.circuit_breaker = route.circuit_breaker || { failures: 5, open_for: '30s' };
    route.cache_policy = $('route-cache').value.trim();
    route.request_transform = route.request_transform || { set_headers: {}, remove_headers: [], json: { add: {}, remove: [], rename: {} } };
    route.response_transform = route.response_transform || { set_headers: {}, remove_headers: [], json: { add: {}, remove: [], rename: {} } };
    route.rewrite_redirects = $('route-redirects').checked;
    route.streaming = $('route-streaming').checked;
    if (!route.name || !route.path_prefix) throw new Error('Route name and path prefix are required.');
    return route;
  }

  async function deployConfigChange(expectedVersion, change, message) {
    var versions = await api('/admin/v1/configs');
    var active = String(versions.active);
    if (expectedVersion && expectedVersion !== active) throw new Error('The active configuration changed. Reopen the route and try again.');
    var configuration = await api('/admin/v1/configs/' + encodeURIComponent(active));
    change(configuration);
    var allVersions = (versions.versions || []).map(Number);
    configuration.version = Math.max(Number(active), allVersions.length ? Math.max.apply(Math, allVersions) : 0) + 1;
    await api('/admin/v1/configs/validate', { method: 'POST', body: configuration });
    await api('/admin/v1/configs', { method: 'POST', body: configuration });
    await api('/admin/v1/configs/' + configuration.version + '/activate', { method: 'POST', headers: { 'If-Match': active } });
    show(message + ' Configuration version ' + configuration.version + ' is active.');
    await Promise.all([loadStatus(true), loadVersions(), loadAudit()]);
    await loadConfig(configuration.version);
  }

  async function saveRoute(event) {
    event.preventDefault();
    var save = $('save-route');
    save.disabled = true;
    try {
      var route = readRoute();
      var original = $('route-original-name').value;
      await deployConfigChange(model.routeBaseVersion, function (configuration) {
        configuration.routes = configuration.routes || [];
        if (!original) {
          configuration.routes.push(route);
          return;
        }
        var index = configuration.routes.findIndex(function (item) { return item.name === original; });
        if (index < 0) throw new Error('Route no longer exists.');
        configuration.routes[index] = route;
      }, original ? 'Route updated.' : 'Route added.');
      $('route-dialog').close();
    } catch (error) { show(error.message, true); }
    finally { save.disabled = false; }
  }

  async function removeRoute(name) {
    if (!window.confirm('Remove route "' + name + '" and activate the change?')) return;
    try {
      await deployConfigChange(model.active, function (configuration) {
        configuration.routes = (configuration.routes || []).filter(function (route) { return route.name !== name; });
        if (!configuration.routes.length) throw new Error('The gateway must keep at least one route.');
      }, 'Route "' + name + '" removed.');
    } catch (error) { show(error.message, true); }
  }

  async function loadDynamicDNS() {
    try {
      var versions = await api('/admin/v1/configs');
      var active = String(versions.active);
      var configuration = await api('/admin/v1/configs/' + encodeURIComponent(active));
      var dynamicDNS = configuration.dynamic_dns || {};
      model.ddnsBaseVersion = active;
      $('ddns-enabled').checked = !!dynamicDNS.enabled;
      $('ddns-check-url').value = dynamicDNS.check_url || '';
      $('ddns-update-url').value = dynamicDNS.update_url || '';
      $('ddns-interval').value = dynamicDNS.interval || '5m';
      $('ddns-timeout').value = dynamicDNS.timeout || '10s';
    } catch (error) { show(error.message, true); }
  }

  async function saveDynamicDNS(event) {
    event.preventDefault();
    var save = $('save-ddns');
    save.disabled = true;
    try {
      var dynamicDNS = {
        enabled: $('ddns-enabled').checked,
        check_url: $('ddns-check-url').value.trim(),
        update_url: $('ddns-update-url').value.trim(),
        interval: $('ddns-interval').value.trim() || '5m',
        timeout: $('ddns-timeout').value.trim() || '10s'
      };
      if (dynamicDNS.enabled && (!dynamicDNS.check_url || !dynamicDNS.update_url)) throw new Error('Both Dynamic DNS URLs are required when the worker is enabled.');
      if (dynamicDNS.enabled && dynamicDNS.update_url.indexOf('{ip}') < 0) throw new Error('The DNS update URL must contain the {ip} placeholder.');
      await deployConfigChange(model.ddnsBaseVersion, function (configuration) { configuration.dynamic_dns = dynamicDNS; }, dynamicDNS.enabled ? 'Dynamic DNS enabled.' : 'Dynamic DNS configuration saved.');
      await loadDynamicDNS();
    } catch (error) { show(error.message, true); }
    finally { save.disabled = false; }
  }

  function renderKeys(data) {
    var body = $('keys-body');
    body.replaceChildren();
    if (!data.api_keys || !data.api_keys.length) {
      var row = make('tr');
      var cell = make('td', 'empty', 'No dynamic API keys have been issued.');
      cell.colSpan = 5;
      row.append(cell);
      body.append(row);
      return;
    }
    data.api_keys.forEach(function (key) {
      var row = make('tr');
      var name = make('td');
      name.append(make('strong', '', key.name));
      name.append(make('small', '', key.id.slice(0, 12) + '…'));
      var scopes = make('td');
      var stack = make('div', 'policy-stack');
      (key.scopes || []).forEach(function (scope) { stack.append(tag(scope)); });
      scopes.append(stack);
      var created = make('td', '', formatDate(key.created_at));
      var state = make('td');
      state.append(tag(key.revoked ? 'Revoked' : 'Active', key.revoked ? 'revoked' : 'active'));
      var actions = make('td');
      if (!key.revoked) actions.append(button('Revoke', 'danger', function () { revokeKey(key); }));
      row.append(name, scopes, created, state, actions);
      body.append(row);
    });
  }

  async function loadKeys() {
    try { renderKeys(await api('/admin/v1/api-keys')); }
    catch (error) { show(error.message, true); }
  }

  async function createKey(event) {
    event.preventDefault();
    var name = $('key-name').value.trim();
    var scopes = $('key-scopes').value.split(/[\s,]+/).filter(Boolean);
    if (!name || !scopes.length) return show('A name and at least one scope are required.', true);
    try {
      var result = await api('/admin/v1/api-keys', { method: 'POST', body: { name: name, scopes: Array.from(new Set(scopes)) } });
      $('new-secret').textContent = result.api_key;
      $('secret-panel').hidden = false;
      $('key-form').reset();
      show('API key created. Copy its secret now.');
      await Promise.all([loadKeys(), loadAudit()]);
    } catch (error) { show(error.message, true); }
  }

  async function revokeKey(key) {
    if (!window.confirm('Revoke API key "' + key.name + '"? Clients using it will immediately lose access.')) return;
    try {
      await api('/admin/v1/api-keys/' + encodeURIComponent(key.id), { method: 'DELETE' });
      show('API key "' + key.name + '" revoked.');
      await Promise.all([loadKeys(), loadAudit()]);
    } catch (error) { show(error.message, true); }
  }

  async function copySecret() {
    var secret = $('new-secret').textContent;
    try {
      await navigator.clipboard.writeText(secret);
      show('API key copied to the clipboard.');
    } catch (_) {
      var range = document.createRange();
      range.selectNodeContents($('new-secret'));
      window.getSelection().removeAllRanges();
      window.getSelection().addRange(range);
      show('Secret selected. Press Ctrl/Cmd+C to copy.');
    }
  }

  async function invalidateCache(event) {
    event.preventDefault();
    var route = $('cache-route').value;
    if (!window.confirm('Invalidate ' + (route ? 'cached responses for ' + route : 'the complete gateway cache') + '?')) return;
    try {
      var result = await api('/admin/v1/cache/invalidate', { method: 'POST', body: { route: route } });
      show(result.deleted + ' cache ' + (result.deleted === 1 ? 'entry' : 'entries') + ' invalidated.');
      await loadAudit();
    } catch (error) { show(error.message, true); }
  }

  function renderAudit(data) {
    var body = $('audit-body');
    body.replaceChildren();
    if (!data.events || !data.events.length) {
      var row = make('tr');
      var cell = make('td', 'empty', 'No administrative events recorded.');
      cell.colSpan = 4;
      row.append(cell);
      body.append(row);
    } else {
      data.events.forEach(function (event) {
        var row = make('tr');
        row.append(make('td', '', formatDate(event.at)), make('td', '', event.actor), make('td', '', event.action), make('td', '', event.target || '—'));
        body.append(row);
      });
    }
    $('audit-page').textContent = 'Page ' + (model.auditPage + 1);
    $('audit-previous').disabled = model.auditPage === 0;
    $('audit-next').disabled = !data.next_cursor;
  }

  async function loadAudit(page) {
    if (page === undefined) {
      page = 0;
      model.auditCursors = [''];
    }
    if (page < 0 || page >= model.auditCursors.length) return;
    try {
      var cursor = model.auditCursors[page];
      var data = await api('/admin/v1/audit?limit=25' + (cursor ? '&before=' + encodeURIComponent(cursor) : ''));
      model.auditPage = page;
      model.auditCursors = model.auditCursors.slice(0, page + 1);
      if (data.next_cursor) model.auditCursors.push(data.next_cursor);
      renderAudit(data);
    }
    catch (error) { show(error.message, true); }
  }

  function bind() {
    $('refresh').addEventListener('click', function () { Promise.all([loadStatus(), loadStatistics(), loadVersions(), loadKeys(), loadAudit(), loadDynamicDNS()]); });
    $('refresh-audit').addEventListener('click', function () { loadAudit(); });
    $('audit-previous').addEventListener('click', function () { loadAudit(model.auditPage - 1); });
    $('audit-next').addEventListener('click', function () { loadAudit(model.auditPage + 1); });
    $('new-config').addEventListener('click', newConfig);
    $('add-route').addEventListener('click', function () { openRoute(''); });
    $('route-form').addEventListener('submit', saveRoute);
    $('close-route').addEventListener('click', function () { $('route-dialog').close(); });
    $('cancel-route').addEventListener('click', function () { $('route-dialog').close(); });
    $('route-dialog').addEventListener('click', function (event) { if (event.target === $('route-dialog')) $('route-dialog').close(); });
    $('format-config').addEventListener('click', function () { try { $('config-editor').value = JSON.stringify(editorJSON(), null, 2); show('Configuration formatted.'); } catch (error) { show(error.message, true); } });
    $('validate-config').addEventListener('click', validateConfig);
    $('save-config').addEventListener('click', saveConfig);
    $('key-form').addEventListener('submit', createKey);
    $('ddns-form').addEventListener('submit', saveDynamicDNS);
    $('copy-secret').addEventListener('click', copySecret);
    $('dismiss-secret').addEventListener('click', function () { $('new-secret').textContent = ''; $('secret-panel').hidden = true; });
    $('cache-form').addEventListener('submit', invalidateCache);
    document.querySelectorAll('.nav-link').forEach(function (link) {
      link.addEventListener('click', function () {
        document.querySelectorAll('.nav-link').forEach(function (item) { item.classList.toggle('active', item === link); });
      });
    });
    document.addEventListener('visibilitychange', function () { if (!document.hidden) loadStatus(true); });
  }

  async function initialize() {
    bind();
    await Promise.all([loadStatus(true), loadStatistics(true), loadVersions(), loadKeys(), loadAudit(), loadDynamicDNS()]);
    if (model.active) await loadConfig(model.active);
    window.setInterval(function () { if (!document.hidden) Promise.all([loadStatus(true), loadStatistics(true)]); }, 15000);
  }

  initialize().catch(function (error) { setConnection(false); show(error.message, true); });
}());
