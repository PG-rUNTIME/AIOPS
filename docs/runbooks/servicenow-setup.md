# ServiceNow setup (per tenant)

1. Integration user with role `evt_mgmt_integration` (EM) or `itil` (Table API fallback).
2. Event rule: source `AIOps`, create incident for severity ≤ 2, bind `node` → CMDB CI by name/`ci_id`.
3. Close-out webhook (business rule on `incident`, after update, when state changes to Resolved/Closed
   and `correlation_display = AIOps`) POSTs to `https://<platform>/feedback/v1/webhooks/servicenow`:

```javascript
(function executeRule(current, previous) {
  var body = {
    tenant_id: gs.getProperty('x_aiops.tenant_id'),
    correlation_id: current.getValue('correlation_id'),
    number: current.getValue('number'),
    close_code: current.getValue('close_code'),
    u_aiops_outcome: current.getValue('u_aiops_outcome'),        // true_positive | false_positive
    u_actual_root_cause: current.getValue('u_actual_root_cause'),
    u_failure_occurred_at: current.getValue('u_failure_occurred_at')
  };
  var payload = JSON.stringify(body);
  var sig = new GlideDigest().getSHA256Hex(gs.getProperty('x_aiops.webhook_secret') + payload); // replace with HMAC via a Script Include
  var r = new sn_ws.RESTMessageV2();
  r.setEndpoint(gs.getProperty('x_aiops.feedback_url'));
  r.setHttpMethod('POST');
  r.setRequestHeader('Content-Type', 'application/json');
  r.setRequestHeader('X-AIOps-Signature', 'sha256=' + sig);
  r.setRequestBody(payload);
  r.executeAsync();
})(current, previous);
```

The feedback service verifies **HMAC-SHA256(secret, body)**; implement the HMAC in a Script Include
(the `GlideDigest` line above is a placeholder and will not verify as-is).
