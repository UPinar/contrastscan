document.addEventListener('DOMContentLoaded', function() {
  var resultData = document.getElementById('result-data');
  var scanId = resultData.getAttribute('data-scan-id');
  var domain = resultData.getAttribute('data-domain');

  /* --- Share / Copy Link --- */
  var shareBtn = document.getElementById('shareBtn');
  if (shareBtn) {
    shareBtn.addEventListener('click', function() {
      navigator.clipboard.writeText(window.location.href);
      shareBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:0.35rem;"><polyline points="20 6 9 17 4 12"/></svg>Copied!';
      shareBtn.style.borderColor = '#22c55e';
      shareBtn.style.color = '#22c55e';
      setTimeout(function() {
        shareBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:0.35rem;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy Link';
        shareBtn.style.borderColor = '#27272a';
        shareBtn.style.color = '#a1a1aa';
      }, 2000);
    });
  }

  /* --- Download Report --- */
  var reportBtn = document.getElementById('reportBtn');
  if (reportBtn) {
    reportBtn.addEventListener('click', function() {
      var label = document.getElementById('reportLabel');
      var icon = document.getElementById('reportIcon');
      reportBtn.disabled = true;
      reportBtn.style.opacity = '0.6';
      reportBtn.style.cursor = 'wait';
      icon.style.display = 'none';
      label.textContent = 'Generating...';

      var hint = document.getElementById('reportHint');
      if (hint) hint.textContent = 'Waiting for passive recon to complete...';
      setTimeout(function() {
        if (hint && reportBtn.disabled) hint.textContent = 'Almost there \u2014 collecting recon data...';
      }, 5000);

      var spinner = document.createElement('span');
      spinner.className = 'sm-spinner';
      spinner.style.marginRight = '0.35rem';
      spinner.style.verticalAlign = 'middle';
      reportBtn.insertBefore(spinner, label);

      fetch('/report/' + scanId + '.txt')
        .then(function(resp) {
          if (!resp.ok) throw new Error('Report failed');
          return resp.blob();
        })
        .then(function(blob) {
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          a.href = url;
          a.download = domain + '-security-report.txt';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          reportBtn.disabled = false;
          reportBtn.style.opacity = '1';
          reportBtn.style.cursor = 'pointer';
          if (spinner.parentNode) spinner.remove();
          icon.style.display = '';
          label.textContent = 'Download Report';
          if (hint) hint.textContent = '';
        })
        .catch(function() {
          reportBtn.disabled = false;
          reportBtn.style.opacity = '1';
          reportBtn.style.cursor = 'pointer';
          if (spinner.parentNode) spinner.remove();
          icon.style.display = '';
          label.textContent = 'Download Report';
          if (hint) hint.textContent = 'Failed \u2014 try again';
        });
    });
  }

  /* --- Findings Toggle --- */
  var findingsHeader = document.querySelector('.findings-header[role="button"]');
  if (findingsHeader) {
    findingsHeader.addEventListener('click', function() {
      var el = document.getElementById('findings-list');
      var arrow = document.getElementById('findings-arrow');
      el.style.display = el.style.display === 'none' ? 'block' : 'none';
      arrow.classList.toggle('open');
      this.setAttribute('aria-expanded', el.style.display !== 'none');
    });
    findingsHeader.addEventListener('keydown', function(event) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        this.click();
      }
    });
  }

  /* --- Recon Polling & Rendering --- */
  function esc(s) {
    if (s == null) return '';
    var d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
  }

  function reconCard(title, rows) {
    return '<div style="margin-bottom:1rem;">' +
      '<div style="font-size:0.9rem;font-weight:700;color:#fafafa;margin-bottom:0.4rem;border-bottom:1px solid #27272a;padding-bottom:0.3rem;">' + esc(title) + '</div>' +
      '<div style="display:flex;flex-direction:column;gap:0.15rem;">' + rows.filter(Boolean).join('') + '</div>' +
      '</div>';
  }

  function row(label, value) {
    if (!value && value !== 0) {
      return '<div style="padding:0.2rem 0;font-size:0.85rem;color:#d4d4d8;">' + esc(label) + '</div>';
    }
    return '<div style="padding:0.2rem 0;font-size:0.85rem;">' +
      '<span style="color:#a1a1aa;font-weight:500;">' + esc(label) + '</span> ' +
      '<span style="color:#d4d4d8;">' + esc(value) + '</span>' +
      '</div>';
  }

  function pollRecon() {
    fetch('/api/recon/' + scanId)
      .then(function(r) { return r.json(); })
      .then(function(resp) {
        if ((resp.status === 'done' || resp.status === 'partial') && resp.data) {
          if (resp.status === 'done') {
            document.getElementById('recon-status').innerHTML = 'Complete';
            document.getElementById('recon-status').className = 'tag pass';
          } else {
            document.getElementById('recon-status').innerHTML = '<span class="spinner"></span>Loading...';
            document.getElementById('recon-status').className = 'tag warn';
          }
          renderRecon(resp.data);
          if (resp.status === 'partial') {
            setTimeout(pollRecon, 2000);
          }
        } else if (resp.status === 'error') {
          document.getElementById('recon-status').textContent = 'Error';
          document.getElementById('recon-status').className = 'tag fail';
        } else {
          setTimeout(pollRecon, 2000);
        }
      })
      .catch(function() { setTimeout(pollRecon, 3000); });
  }

  function renderRecon(d) {
    var html = '';

    if (d.whois && d.whois.registrar) {
      var whoisRows = [
        row('Registrar', d.whois.registrar),
        row('Created', d.whois.creation_date || 'N/A'),
        row('Expires', d.whois.expiry_date || 'N/A'),
      ];
      if (d.whois.name_servers && d.whois.name_servers.length > 0) {
        d.whois.name_servers.forEach(function(ns) { whoisRows.push(row('NS', ns)); });
      }
      html += reconCard('1. WHOIS', whoisRows);
    }

    if (d.reverse_dns && d.reverse_dns.ip) {
      var rdnsRows = [];
      if (d.reverse_dns.ipv4) rdnsRows.push(row('IPv4', d.reverse_dns.ipv4));
      if (d.reverse_dns.ipv6) rdnsRows.push(row('IPv6', d.reverse_dns.ipv6));
      if (!d.reverse_dns.ipv4 && !d.reverse_dns.ipv6) rdnsRows.push(row('IP', d.reverse_dns.ip));
      if (d.reverse_dns.ptr) rdnsRows.push(row('PTR', d.reverse_dns.ptr));
      html += reconCard('2. Infrastructure', rdnsRows);
    }

    if (d.ns_records && d.ns_records.ns_records && d.ns_records.ns_records.length > 0) {
      var nsRows = d.ns_records.ns_records.map(function(ns) {
        var val = ns.ip ? '(' + ns.ip + ')' : '(IP unknown)';
        return row(ns.hostname, val);
      });
      html += reconCard('2b. Nameservers (' + d.ns_records.count + ')', nsRows);
    }

    var fpRows = [];
    if (d.tech_stack && d.tech_stack.count > 0) {
      d.tech_stack.technologies.forEach(function(t) {
        fpRows.push(row(t.name, t.source || ''));
      });
    }
    if (d.waf && d.waf.waf_present) {
      d.waf.detected.forEach(function(w) { fpRows.push(row('WAF: ' + w, '')); });
    }
    if (d.http_version) {
      fpRows.push(row('Protocol', (d.http_version.negotiated || 'unknown').toUpperCase()));
    }
    if (fpRows.length > 0) {
      html += reconCard('3. Fingerprint', fpRows);
    }

    if (d.subdomains && d.subdomains.count > 0) {
      var subRows = d.subdomains.subdomains.slice(0, 15).map(function(s) { return row(s, ''); });
      if (d.subdomains.count > 15) subRows.push(row('... and ' + (d.subdomains.count - 15) + ' more', ''));
      html += reconCard('4. Subdomains (' + d.subdomains.count + ')', subRows);
    }

    if (d.subdomain_takeover && d.subdomain_takeover.checked > 0) {
      var toRows = [];
      if (d.subdomain_takeover.vulnerable && d.subdomain_takeover.vulnerable.length > 0) {
        d.subdomain_takeover.vulnerable.forEach(function(v) {
          toRows.push(row(v.subdomain, v.service + ' \u2014 ' + v.evidence));
        });
        html += reconCard('\u26a0 Subdomain Takeover (' + d.subdomain_takeover.vulnerable.length + ' vulnerable)', toRows);
      } else {
        toRows.push(row('Checked', d.subdomain_takeover.checked + ' subdomains (' + d.subdomain_takeover.cname_count + ' CNAMEs)'));
        toRows.push(row('Result', 'No dangling CNAMEs found'));
        html += reconCard('4b. Subdomain Takeover', toRows);
      }
    }

    if (d.zone_transfer && d.zone_transfer.vulnerable) {
      html += reconCard('5. Zone Transfer \u26a0', [
        row('AXFR Open', d.zone_transfer.record_count ? d.zone_transfer.record_count + ' records exposed' : 'Vulnerable'),
      ]);
    } else {
      html += reconCard('5. Zone Transfer', [
        row('AXFR', 'Not vulnerable'),
      ]);
    }

    if (d.robots && d.robots.exists && d.robots.disallowed_paths && d.robots.disallowed_paths.length > 0) {
      var robotRows = [];
      d.robots.disallowed_paths.slice(0, 10).forEach(function(p) { robotRows.push(row(p, '')); });
      if (d.robots.disallowed_paths.length > 10) robotRows.push(row('... and ' + (d.robots.disallowed_paths.length - 10) + ' more', ''));
      html += reconCard('6. robots.txt (' + d.robots.disallowed_paths.length + ' disallowed)', robotRows);
    } else {
      html += reconCard('6. robots.txt', [
        row('Result', 'Not found'),
      ]);
    }

    if (d.ct_logs && !d.ct_logs.error && d.ct_logs.total_certificates > 0) {
      var ctRows = [row('Total', String(d.ct_logs.total_certificates))];
      if (d.ct_logs.recent_certificates && d.ct_logs.recent_certificates.length > 0) {
        d.ct_logs.recent_certificates.slice(0, 5).forEach(function(c) {
          ctRows.push(row(c.common_name || 'N/A', c.not_before + ' \u2014 ' + c.not_after));
        });
      }
      html += reconCard('7. Certificate Transparency', ctRows);
    }

    if (d.emails && d.emails.found && d.emails.found.length > 0) {
      var emailRows = d.emails.found.map(function(e) { return row(e, ''); });
      html += reconCard('8. Email (MX)', emailRows);
    }

    if (d.asn && d.asn.asn) {
      var asnRows = [
        row('ASN', 'AS' + d.asn.asn),
        row('Organization', d.asn.asn_name || 'N/A'),
      ];
      if (d.asn.ipv4_prefixes && d.asn.ipv4_prefixes.length > 0) {
        d.asn.ipv4_prefixes.slice(0, 5).forEach(function(p) { asnRows.push(row('IPv4', p.prefix)); });
        if (d.asn.ipv4_prefixes.length > 5) asnRows.push(row('', '+' + (d.asn.ipv4_prefixes.length - 5) + ' more IPv4 prefixes'));
      }
      if (d.asn.ipv6_prefixes && d.asn.ipv6_prefixes.length > 0 && d.asn.ipv4_prefixes && d.asn.ipv4_prefixes.length > 0) {
        asnRows.push(row('', ''));
      }
      if (d.asn.ipv6_prefixes && d.asn.ipv6_prefixes.length > 0) {
        d.asn.ipv6_prefixes.slice(0, 3).forEach(function(p) { asnRows.push(row('IPv6', p.prefix)); });
        if (d.asn.ipv6_prefixes.length > 3) asnRows.push(row('', '+' + (d.asn.ipv6_prefixes.length - 3) + ' more IPv6 prefixes'));
      }
      html += reconCard('9. Network Range', asnRows);
    }

    {
      var secRows = [];
      if (d.security_txt && d.security_txt.found && d.security_txt.fields) {
        var f = d.security_txt.fields;
        if (f.contact) {
          var contacts = Array.isArray(f.contact) ? f.contact : [f.contact];
          contacts.forEach(function(c) { secRows.push(row('Contact', c)); });
        }
        if (f.policy) secRows.push(row('Policy', f.policy));
        if (f.expires) secRows.push(row('Expires', f.expires));
        if (f.encryption) secRows.push(row('Encryption', f.encryption));
        if (f.acknowledgments) secRows.push(row('Acknowledgments', f.acknowledgments));
      } else {
        secRows.push(row('Not found', ''));
      }
      html += reconCard('10. Security Contact', secRows);
    }

    {
      var caaRows = [];
      if (d.caa && d.caa.found && d.caa.issuers && d.caa.issuers.length > 0) {
        d.caa.issuers.forEach(function(issuer) { caaRows.push(row('Allowed CA', issuer)); });
        if (d.caa.records) {
          d.caa.records.forEach(function(r) {
            if (r.tag === 'iodef') caaRows.push(row('Report to', r.value));
          });
        }
      } else {
        caaRows.push(row('No CAA records', ''));
      }
      html += reconCard('11. CAA Records', caaRows);
    }

    document.getElementById('recon-data').innerHTML = html || '<p style="color:#71717a;font-size:0.8rem;">No recon data available.</p>';
  }

  pollRecon();
});
