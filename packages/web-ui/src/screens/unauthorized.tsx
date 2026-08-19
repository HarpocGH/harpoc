import { useState } from "preact/hooks";
import { setToken } from "../auth/token-store";

export function Unauthorized({ onToken }: { onToken: () => void }) {
  const [value, setValue] = useState("");
  return (
    <div class="takeover">
      <h1>Sign in</h1>
      <p>
        Start the server with <code>harpoc server start --rest --ui</code> and open the printed
        link, or paste a token minted with <code>harpoc auth token</code>.
      </p>
      <form
        class="panel"
        onSubmit={(e) => {
          e.preventDefault();
          if (value.trim() === "") return;
          setToken(value.trim());
          onToken();
        }}
      >
        <label for="token">API token</label>
        <input
          id="token"
          type="password"
          value={value}
          onInput={(e) => setValue(e.currentTarget.value)}
        />
        <button type="submit">Use token</button>
      </form>
    </div>
  );
}
