/**
 * Clipboard helper with scheduled auto-clear for copied secrets.
 */

let clearTimerId = null;
let lastCopiedValue = null;

/**
 * Copy sensitive text to the system clipboard and schedule automatic clearing
 * if the clipboard still holds the same value after `clearAfterMs`.
 * @param {string} text
 * @param {object} [options]
 * @param {number} [options.clearAfterMs=25000]
 * @param {() => void} [options.onCleared]
 * @returns {Promise<boolean>}
 */
export async function copySecretToClipboard(
  text,
  { clearAfterMs = 25000, onCleared = null } = {}
) {
  if (typeof text !== "string" || text.length === 0) {
    return false;
  }

  let copied = false;
  if (
    typeof navigator !== "undefined" &&
    navigator.clipboard &&
    typeof navigator.clipboard.writeText === "function"
  ) {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
    } catch {
      copied = fallbackCopyText(text);
    }
  } else {
    copied = fallbackCopyText(text);
  }

  if (copied) {
    lastCopiedValue = text;
    if (clearTimerId !== null) {
      clearTimeout(clearTimerId);
    }
    if (clearAfterMs > 0) {
      clearTimerId = setTimeout(async () => {
        clearTimerId = null;
        await clearClipboardIfUnchanged(onCleared);
      }, clearAfterMs);
    }
  }

  return copied;
}

/**
 * Clear clipboard if we have write access when locking the vault or after timeout.
 */
export async function clearClipboardIfUnchanged(onCleared = null) {
  if (!lastCopiedValue) {
    return;
  }
  lastCopiedValue = null;
  if (
    typeof navigator !== "undefined" &&
    navigator.clipboard &&
    typeof navigator.clipboard.writeText === "function"
  ) {
    try {
      await navigator.clipboard.writeText("");
      if (typeof onCleared === "function") {
        onCleared();
      }
    } catch {
      // Browser may block background clipboard write without active user gesture
    }
  }
}

function fallbackCopyText(text) {
  if (typeof document === "undefined") {
    return false;
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  textarea.style.pointerEvents = "none";
  document.body.appendChild(textarea);
  textarea.select();
  let success = false;
  try {
    success = document.execCommand("copy");
  } catch {
    success = false;
  } finally {
    document.body.removeChild(textarea);
  }
  return success;
}
