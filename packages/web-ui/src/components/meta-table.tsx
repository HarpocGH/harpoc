/**
 * Generic key-and-value renderer for detail panels: it shows whatever the
 * metadata-only API returned and nothing more — no hand-listed field set to
 * drift out of sync with the wire, and nothing here to teach it a new route.
 */
export function MetaTable({ entries }: { entries: Record<string, unknown> }) {
  const rows = Object.entries(entries).filter(([, v]) => v !== undefined);
  if (rows.length === 0) return <p class="empty">No data.</p>;
  return (
    <table>
      <tbody>
        {rows.map(([key, value]) => (
          <tr key={key}>
            <th scope="row">{key}</th>
            <td>{typeof value === "object" ? JSON.stringify(value) : String(value)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
