# 📧 Email Insight Analyzer

**Email Insight Analyzer** is a serverless, web-based forensic tool built on **Google Apps Script**. It transforms complex, raw email headers into clear, actionable insights, helping sysadmins, security analysts, and developers diagnose delivery issues and verify email authenticity.



## ✨ Key Features

* **🔍 Deep Header Analysis:** Automatically decodes MIME Encoded-Words (UTF-8, Base64, Quoted-Printable) to display readable Subjects and Sender names.
* **🛡️ Advanced Security Verification:**
    * **SPF & DKIM:** Extracts and verifies results, including support for `X-Original-Authentication-Results` to handle forwarded emails (Google Groups/DLs) correctly.
    * **DMARC:** Performs recursive DNS lookups to find policies inherited from parent domains.
    * **BIMI:** Fetches and displays the Brand Indicator (SVG Logo) directly from DNS records.
* **⏱️ Visual Hop Timeline:** Replaces boring tables with a vertical "shipping-tracker" style timeline. It visualizes server hops and highlights latency bottlenecks with color-coded bars (Green/Yellow/Red).
* **📋 Smart Summary:** One-click copy for essential fields (Message-ID, Date, X-Mailer, etc.).
* **📄 PDF Reporting:** Generate and download a clean, professional PDF report of the analysis directly from the browser (powered by `html2pdf.js`).
* **☁️ Serverless:** Runs entirely within your Google Workspace/Gmail account context. No external servers required.

## 🚀 Installation & Setup

Since this is a Google Apps Script project, you don't need `npm` or a server.

1.  **Create a Project:**
    * Go to [script.google.com](https://script.google.com/).
    * Click **"New Project"**.
    * Name it `Email Insight Analyzer`.

2.  **Add the Backend Code:**
    * Open the `Code.gs` file.
    * Copy the content of `Code.js` from this repository and paste it there.
    * Save (`Ctrl+S`).

3.  **Add the Frontend Code:**
    * Click the **+** icon next to "Files" and select **HTML**.
    * Name the file `Index` (it will become `Index.html`).
    * Copy the content of `Index.html` from this repository and paste it there.
    * Save.

4.  **Deploy as Web App:**
    * Click **Deploy** (blue button top right) > **New deployment**.
    * Select type: **Web app**.
    * **Description:** "v1".
    * **Execute as:** "Me" (your email).
    * **Who has access:** "Anyone" (or "Only myself" if you want it private).
    * Click **Deploy**.

5.  **Run:**
    * Copy the **Web App URL** provided after deployment.
    * Open it in your browser.

## 🛠️ Usage

1.  Open the "Show Original" or "View Source" option in your email client (Gmail, Outlook, Thunderbird, etc.).
2.  Copy the entire raw text (Headers + Body).
3.  Paste it into the **Email Insight Analyzer** text area.
4.  Click **ANALYZE MESSAGE**.
5.  View the results:
    * Check the **Summary Card** for sender info and DMARC/BIMI status.
    * Review the **Timeline** to see where the email was delayed.
    * Use the **PDF** button to save a report.

## 📦 Technologies Used

* **Google Apps Script:** Backend logic and DNS resolution (`UrlFetchApp`).
* **Bootstrap 5:** Responsive UI and styling.
* **html2pdf.js:** Client-side PDF generation.
* **Vanilla JS:** Frontend logic and DOM manipulation.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1.  Fork the project.
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---
*Built with ❤️ using Google Apps Script.*
