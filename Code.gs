function doGet() {
  return HtmlService.createTemplateFromFile('Index').evaluate()
      .setTitle('Email Insight Analyzer')
      .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

function processRawEmail(rawText) {
  const result = {
    headers: [],
    hops: [],
    security: {
      spf: { result: "NONE", ip: "" },
      dkim: { result: "NONE", domain: "" }
    },
    summary: { 
      subject: "N/A",
      from: "N/A",
      to: "N/A",
      date: "N/A",
      messageId: "N/A",
      xmailer: "N/A", // <--- NUOVO CAMPO
      dmarc: "Verifica in corso...",
      bimi: "Verifica in corso..." 
    },
    content: ""
  };

  try {
    if (!rawText) return result;

    const normalized = rawText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const splitIndex = normalized.search(/\n\n/);
    const headerPart = splitIndex > -1 ? normalized.substring(0, splitIndex) : normalized;
    const bodyPart = splitIndex > -1 ? normalized.substring(splitIndex).trim() : "";

    const unfoldedHeaders = headerPart.replace(/\n[ \t]+/g, ' ');
    const headerLines = unfoldedHeaders.split('\n');

    // === 1. PARSING HEADERS ===
    headerLines.forEach(line => {
      const colonPos = line.indexOf(':');
      if (colonPos > 0) {
        const key = line.substring(0, colonPos).trim();
        let rawValue = line.substring(colonPos + 1).trim();
        
        // DECODIFICA HEADER
        const value = decodeHeader(rawValue);

        result.headers.push({ key, value });

        const kL = key.toLowerCase();
        const vL = value.toLowerCase();

        // Summary Info
        if (kL === 'subject') result.summary.subject = value;
        if (kL === 'from') result.summary.from = value;
        if (kL === 'to') result.summary.to = value;
        if (kL === 'date') result.summary.date = value;
        if (kL === 'message-id') result.summary.messageId = value;
        if (kL === 'x-mailer') result.summary.xmailer = value; // <--- ESTRAZIONE X-MAILER

        // Security Analysis: Cerca sia Auth-Results STANDARD che ORIGINAL (per DL/Groups)
        if (kL === 'authentication-results' || kL === 'x-original-authentication-results') {
          
          // SPF Parsing
          if (vL.includes('spf=pass')) {
            result.security.spf.result = "PASS";
            const ipMatch = value.match(/(?:sender ip is|ip=|client-ip=)\s*([0-9a-f\.:]+)/i);
            if (ipMatch) result.security.spf.ip = ipMatch[1];
          } else if (vL.includes('spf=fail')) {
             result.security.spf.result = "FAIL";
          } else if (vL.includes('spf=softfail')) {
             result.security.spf.result = "SOFTFAIL";
          }

          // DKIM Parsing
          if (vL.includes('dkim=pass')) {
            result.security.dkim.result = "PASS";
          } else if (vL.includes('dkim=fail')) {
            result.security.dkim.result = "FAIL";
          }

          // DKIM Domain Extraction
          const domMatch = value.match(/header\.d\s*=\s*([a-zA-Z0-9\-\.]+)/i);
          if (domMatch) {
             result.security.dkim.domain = domMatch[1];
          }
        }
        
        // Fallback SPF
        if (kL === 'received-spf' && !result.security.spf.ip) {
           const ipMatch = value.match(/(?:client-ip|ip)\s*=\s*([0-9a-f\.:]+)/i);
           if (ipMatch) result.security.spf.ip = ipMatch[1];
           if (vL.startsWith('pass') && result.security.spf.result === "NONE") result.security.spf.result = "PASS";
        }

        // Fallback DKIM Domain
        if (kL === 'dkim-signature' && !result.security.dkim.domain) {
            const dMatch = value.match(/\bd\s*=\s*([a-zA-Z0-9\-\.]+)/i);
            if (dMatch) result.security.dkim.domain = dMatch[1];
        }
      }
    });

    // === 2. DNS LOOKUPS (DMARC & BIMI) ===
    if (result.summary.from !== "N/A") {
      // Estrae dominio gestendo anche formati complessi o DL
      const emailMatch = result.summary.from.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/);
      let domain = "";
      
      if (emailMatch) {
         const email = emailMatch[0];
         domain = email.split('@')[1];
      }

      if (domain) {
        result.summary.dmarc = getDmarcRecursive(domain);
        result.summary.bimi = getBimiRecursive(domain);
      } else {
        result.summary.dmarc = "Dominio non rilevato";
        result.summary.bimi = "Dominio non rilevato";
      }
    } else {
      result.summary.dmarc = "Mittente non trovato";
      result.summary.bimi = "Mittente non trovato";
    }

    // === 3. HOPS ANALYSIS ===
    const receivedHeaders = result.headers.filter(h => h.key.toLowerCase() === 'received').reverse();
    let lastTime = null;
    let hopId = 1;

    receivedHeaders.forEach(h => {
      const v = h.value;
      const dateParts = v.split(';'); 
      const dateStr = dateParts.length > 1 ? dateParts[dateParts.length - 1].trim() : null;
      let currentTime = dateStr ? new Date(dateStr) : null;

      const ipMatch = v.match(/\[([0-9a-f\.:]+)\]/i) || v.match(/\(([0-9a-f\.:]+)\)/i);
      const ip = ipMatch ? ipMatch[1] : null;

      const fromMatch = v.match(/from\s+([^\s\(\[]+)/i);
      const byMatch = v.match(/by\s+([^\s\(\[]+)/i);
      
      let fromHost = fromMatch ? fromMatch[1] : (ip ? "Unknown Host" : "Unknown");
      let toHost = byMatch ? byMatch[1] : "Unknown";
      if(fromHost.length > 50) fromHost = fromHost.substring(0,47) + "...";

      let delay = 0;
      if (lastTime && currentTime && !isNaN(currentTime.getTime())) {
        delay = Math.max(0, Math.floor((currentTime - lastTime) / 1000));
      }
      if (currentTime && !isNaN(currentTime.getTime())) lastTime = currentTime;

      result.hops.push({
        id: hopId++,
        from: ip ? `${fromHost} (${ip})` : fromHost,
        to: toHost,
        delay: delay
      });

      if (!result.security.spf.ip && ip) {
          if (!ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.')) result.security.spf.ip = ip; 
      }
    });

    result.content = parseMimeRecursive(bodyPart, headerPart);
    return result;
  } catch (e) {
    return { headers: [], hops: [], security: {spf:{}, dkim:{}}, summary:{}, content: "Error: " + e.toString() };
  }
}

// === HELPER FUNCTIONS ===

function decodeHeader(text) {
  if (!text) return "";
  return text.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, function(match, charset, encoding, data) {
    try {
      if (encoding.toUpperCase() === 'B') {
        const bytes = Utilities.base64Decode(data);
        return Utilities.newBlob(bytes).getDataAsString(charset);
      } else if (encoding.toUpperCase() === 'Q') {
        let decoded = data.replace(/_/g, ' ');
        decoded = decoded.replace(/=([0-9A-F]{2})/gi, function(m, hex) {
           return String.fromCharCode(parseInt(hex, 16));
        });
        try { return decodeURIComponent(escape(decoded)); } catch(e) { return decoded; }
      }
    } catch (e) { return match; }
    return match;
  });
}

function getDmarcRecursive(fullDomain) {
  let currentDomain = fullDomain;
  let parts = currentDomain.split('.');
  while (parts.length >= 2) {
    const policy = fetchDmarcRecord(currentDomain);
    if (policy) return (currentDomain === fullDomain) ? policy : policy + " (ereditata da " + currentDomain + ")";
    parts.shift();
    currentDomain = parts.join('.');
  }
  return "Il mittente non ha una policy DMARC";
}

function fetchDmarcRecord(domain) {
  try {
    const url = `https://dns.google/resolve?name=_dmarc.${domain}&type=TXT`;
    const response = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
    const json = JSON.parse(response.getContentText());
    if (json.Answer && json.Answer.length > 0) {
      for (let i = 0; i < json.Answer.length; i++) {
        let data = json.Answer[i].data.replace(/^"|"$/g, ''); 
        if (data.includes('v=DMARC1')) return data;
      }
    }
  } catch (e) { console.log("DMARC Error: " + e.message); }
  return null;
}

function getBimiRecursive(fullDomain) {
  let currentDomain = fullDomain;
  let parts = currentDomain.split('.');
  while (parts.length >= 2) {
    const bimiUrl = fetchBimiRecord(currentDomain);
    if (bimiUrl) return bimiUrl;
    parts.shift();
    currentDomain = parts.join('.');
  }
  return "Nessun BIMI trovato";
}

function fetchBimiRecord(domain) {
  try {
    const url = `https://dns.google/resolve?name=default._bimi.${domain}&type=TXT`;
    const response = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
    const json = JSON.parse(response.getContentText());
    if (json.Answer && json.Answer.length > 0) {
      for (let i = 0; i < json.Answer.length; i++) {
        let data = json.Answer[i].data.replace(/^"|"$/g, ''); 
        if (data.includes('v=BIMI1')) {
          const match = data.match(/l=([^;]+)/i);
          if (match && match[1]) return match[1].trim();
        }
      }
    }
  } catch (e) { console.log("BIMI Error: " + e.message); }
  return null;
}

function parseMimeRecursive(body, headers) {
  const boundaryMatch = headers.match(/boundary=["']?([^"';\s]+)["']?/i);
  if (!boundaryMatch) return decodeData(body, headers);
  const boundary = boundaryMatch[1];
  const parts = body.split(new RegExp('--' + boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?:--)?', 'g'));
  let htmlPart = ""; let textPart = "";
  for (let part of parts) {
    if (part.trim() === "" || part.trim() === "--") continue;
    const splitIndex = part.search(/\n\n/);
    const innerHeaders = splitIndex > -1 ? part.substring(0, splitIndex) : "";
    const innerBody = splitIndex > -1 ? part.substring(splitIndex).trim() : part.trim();
    if (/multipart\//i.test(innerHeaders)) {
      const nested = parseMimeRecursive(innerBody, innerHeaders);
      if (nested) return nested;
    }
    if (/text\/html/i.test(innerHeaders)) htmlPart = decodeData(innerBody, innerHeaders);
    else if (/text\/plain/i.test(innerHeaders)) textPart = decodeData(innerBody, innerHeaders);
  }
  return htmlPart || (textPart ? `<pre style="white-space: pre-wrap;">${textPart}</pre>` : "");
}

function decodeData(content, headers) {
  let output = content;
  const hL = headers.toLowerCase();
  if (hL.includes('content-transfer-encoding: base64')) {
    try {
      const decodedBytes = Utilities.base64Decode(content.replace(/\s/g, ''));
      output = Utilities.newBlob(decodedBytes).getDataAsString("UTF-8");
    } catch (e) { output = "Error decoding Base64"; }
  } else if (hL.includes('quoted-printable')) {
    output = content.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (m, hex) => String.fromCharCode(parseInt(hex, 16)));
    try { output = decodeURIComponent(escape(output)); } catch(e) {}
  }
  return output;
}
