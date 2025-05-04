async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  return hashHex;
}

function evaluateStrength(password) {
  let strength = "Weak";
  if (password.length >= 12 && /[A-Z]/.test(password) &&
      /[a-z]/.test(password) && /\d/.test(password) &&
      /[!@#\$%\^&\*]/.test(password)) {
    strength = "Strong";
  } else if (password.length >= 8 && (/[A-Z]/.test(password) || /\d/.test(password))) {
    strength = "Medium";
  }
  return strength;
}

const weakHashes = [
  "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", // "password"
  "e99a18c428cb38d5f260853678922e03abd8334a", // "abc123"
];

async function checkPassword() {
  const password = document.getElementById("password").value;
  const strength = evaluateStrength(password);
  const hash = await hashPassword(password);

  document.getElementById("strength").innerText = `Strength: ${strength}`;
  document.getElementById("hash").innerText = `SHA-256 Hash: ${hash}`;

  if (weakHashes.includes(hash)) {
    document.getElementById("weak-alert").innerText = "⚠️ This password is known to be weak!";
  } else {
    document.getElementById("weak-alert").innerText = "";
  }
}
