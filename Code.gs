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
      xmailer: "N/A",
      dmarc: "Verifying...",
      bimi: "Verifying..." 
    },
    content: ""
  };

  try {
    if (!rawText) return result;

    // Normalize line endings
    const normalized = rawText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const splitIndex = normalized.search(/\n\n/);
    
    // Separate headers from body
    const headerPart = splitIndex > -1 ? normalized.substring(0, splitIndex) : normalized;
    const bodyPart = splitIndex > -1 ? normalized.substring(splitIndex).trim() : "";

    // Unfold multi-line headers
    const unfoldedHeaders = headerPart.replace(/\n[ \t]+/g, ' ');
    const headerLines = unfoldedHeaders.split('\n');

    // === 1. HEADER PARSING ===
    headerLines.forEach(line => {
      const colonPos = line.indexOf(':');
      if (colonPos > 0) {
        const key = line.substring(0, colonPos).trim();
        let rawValue = line.substring(colonPos + 1).trim();
        
        // Decode MIME encoded-words (e.g., UTF-8 subjects)
        const value = decodeHeader(rawValue);

        result.headers.push({ key, value });

        const kL = key.toLowerCase();
        const vL = value.toLowerCase();

        // Extract summary fields
        if (kL === 'subject') result.summary.subject = value;
        if (kL === 'from') result.summary.from = value;
        if (kL === 'to') result.summary.to = value;
        if (kL === 'date') result.summary.date = value;
        if (kL === 'message-id') result.summary.messageId = value;
        if (kL === 'x-mailer') result.summary.xmailer = value;

        // Security Analysis: Check both standard and original authentication results
        // 'x-original-authentication-results' is critical for forwarded emails (e.g., Google Groups)
        if (kL === 'authentication-results' || kL === 'x-original-authentication-results') {
          
          // SPF Analysis
          if (vL.includes('spf=pass')) {
            result.security.spf.result = "PASS";
            const ipMatch = value.match(/(?:sender ip is|ip=|client-ip=)\s*([0-9a-f\.:]+)/i);
            if (ipMatch) result.security.spf.ip = ipMatch[1];
          } else if (vL.includes('spf=fail')) {
             result.security.spf.result = "FAIL";
          } else if (vL.includes('spf=softfail')) {
             result.security.spf.result = "SOFTFAIL";
          }

          // DKIM Analysis
          if (vL.includes('dkim=pass')) {
            result.security.dkim.result = "PASS";
          } else if (vL.includes('dkim=fail')) {
            result.security.dkim.result = "FAIL";
          }

          // Extract DKIM domain
          const domMatch = value.match(/header\.d\s*=\s*([a-zA-Z0-9\-\.]+)/i);
          if (domMatch) {
             result.security.dkim.domain = domMatch[1];
          }
        }
        
        // Fallback: Check Received-SPF if main auth header is missing IP
        if (kL === 'received-spf' && !result.security.spf.ip) {
           const ipMatch = value.match(/(?:client-ip|ip)\s*=\s*([0-9a-f\.:]+)/i);
           if (ipMatch) result.security.spf.ip = ipMatch[1];
           if (vL.startsWith('pass') && result.security.spf.result === "NONE") result.security.spf.result = "PASS";
        }

        // Fallback: Check direct DKIM-Signature if Auth-Results is inconclusive
        if (kL === 'dkim-signature' && !result.security.dkim.domain) {
            const dMatch = value.match(/\bd\s*=\s*([a-zA-Z0-9\-\.]+)/i);
            if (dMatch) result.security.dkim.domain = dMatch[1];
        }
      }
    });

    // === 2. DNS LOOKUPS (DMARC & BIMI) ===
    if (result.summary.from !== "N/A") {
      // Extract domain from sender address, handling complex formats or DLs
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
        result.summary.dmarc = "Domain not detected";
        result.summary.bimi = "Domain not detected";
      }
    } else {
      result.summary.dmarc = "Sender not found";
      result.summary.bimi = "Sender not found";
    }

    // === 3. HOP ANALYSIS ===
    // Filter Received headers and reverse to establish chronological order
    const receivedHeaders = result.headers.filter(h => h.key.toLowerCase() === 'received').reverse();
    let lastTime = null;
    let hopId = 1;

    receivedHeaders.forEach(h => {
      const v = h.value;
      const dateParts = v.split(';'); 
      const dateStr = dateParts.length > 1 ? dateParts[dateParts.length - 1].trim() : null;
      let currentTime = dateStr ? new Date(dateStr) : null;

      // Extract IP (IPv4/IPv6)
      const ipMatch = v.match(/\[([0-9a-f\.:]+)\]/i) || v.match(/\(([0-9a-f\.:]+)\)/i);
      const ip = ipMatch ? ipMatch[1] : null;

      // Parse 'from' and 'by' hosts
      const fromMatch = v.match(/from\s+([^\s\(\[]+)/i);
      const byMatch = v.match(/by\s+([^\s\(\[]+)/i);
      
      let fromHost = fromMatch ? fromMatch[1] : (ip ? "Unknown Host" : "Unknown");
      let toHost = byMatch ? byMatch[1] : "Unknown";
      
      // Truncate excessively long hostnames
      if(fromHost.length > 50) fromHost = fromHost.substring(0,47) + "...";

      // Calculate delay between hops
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

      // Use the first public IP found as the SPF candidate if not already set
      if (!result.security.spf.ip && ip) {
          if (!ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('127.')) result.security.spf.ip = ip; 
      }
    });

    result.content = parseMimeRecursive(bodyPart, headerPart);
    return result;
  } catch (e) {
    return { headers: [], hops: [], security: {spf:{}, dkim:{}}, summary:{}, content: "Processing Error: " + e.toString() };
  }
}

// === HELPER FUNCTIONS ===

/**
 * Decodes MIME encoded-word strings (RFC 2047).
 * Supports both Base64 (B) and Quoted-Printable (Q) encodings.
 */
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

/**
 * Recursively checks for DMARC records, handling subdomain inheritance.
 */
function getDmarcRecursive(fullDomain) {
  let currentDomain = fullDomain;
  let parts = currentDomain.split('.');
  
  // Traverse up the domain hierarchy
  while (parts.length >= 2) {
    const policy = fetchDmarcRecord(currentDomain);
    if (policy) return (currentDomain === fullDomain) ? policy : policy + " (inherited from " + currentDomain + ")";
    parts.shift();
    currentDomain = parts.join('.');
  }
  return "No DMARC policy found";
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
  } catch (e) { console.log("DMARC Lookup Error: " + e.message); }
  return null;
}

/**
 * Recursively checks for BIMI records (Brand Indicators for Message Identification).
 */
function getBimiRecursive(fullDomain) {
  let currentDomain = fullDomain;
  let parts = currentDomain.split('.');
  
  while (parts.length >= 2) {
    const bimiUrl = fetchBimiRecord(currentDomain);
    if (bimiUrl) return bimiUrl;
    parts.shift();
    currentDomain = parts.join('.');
  }
  return "No BIMI record found";
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
  } catch (e) { console.log("BIMI Lookup Error: " + e.message); }
  return null;
}

/**
 * Recursively parses MIME multipart messages.
 */
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

/**
 * Decodes body content based on Content-Transfer-Encoding.
 */
function decodeData(content, headers) {
  let output = content;
  const hL = headers.toLowerCase();
  
  if (hL.includes('content-transfer-encoding: base64')) {
    try {
      const decodedBytes = Utilities.base64Decode(content.replace(/\s/g, ''));
      output = Utilities.newBlob(decodedBytes).getDataAsString("UTF-8");
    } catch (e) { output = "Error decoding Base64 content"; }
  } else if (hL.includes('quoted-printable')) {
    output = content.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (m, hex) => String.fromCharCode(parseInt(hex, 16)));
    try { output = decodeURIComponent(escape(output)); } catch(e) {}
  }
  return output;
}
