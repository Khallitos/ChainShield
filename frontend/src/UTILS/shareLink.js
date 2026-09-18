function base64UrlEncode(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlDecodeToBytes(s) {
  const padded = s.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((s.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function encodeNote(note) {
  if (!note) return "";
  const bytes = new TextEncoder().encode(note);
  return base64UrlEncode(bytes);
}

export function decodeNote(encoded) {
  if (!encoded) return "";
  try {
    const bytes = base64UrlDecodeToBytes(encoded);
    return new TextDecoder().decode(bytes);
  } catch {
    return "";
  }
}

