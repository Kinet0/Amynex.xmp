// phishing-rules.js
// Define reusable phishing rules and domain patterns for the extension.

const phishingRules = {
  urlKeywords: [
    "login",
    "signin",
    "verify",
    "secure",
    "update",
    "account",
    "password",
    "banking",
    "confirm"
  ],
  lookalikePatterns: [
    /paypa1\./i,
    /amaz0n\./i,
    /micr0soft\./i,
    /g00gle\./i,
    /apple-login/i,
    /banking-secure/i,
    /security-update/i
  ],
  popularBrands: [
    "paypal",
    "amazon",
    "google",
    "microsoft",
    "apple",
    "bank"
  ]
};

export default phishingRules;
