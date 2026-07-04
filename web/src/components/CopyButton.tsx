import { useState } from "react";

export function CopyButton({
  text,
  label = "Copy",
}: {
  text: string;
  label?: string;
}) {
  const [done, setDone] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      setTimeout(() => setDone(false), 1200);
    } catch {
      // Clipboard access can be blocked (e.g. non-secure context); ignore.
    }
  }

  return (
    <button className="copy" type="button" onClick={copy}>
      {done ? "Copied" : label}
    </button>
  );
}
