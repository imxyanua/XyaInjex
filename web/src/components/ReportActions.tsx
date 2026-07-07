import { downloadJson, downloadText } from "../report";

export function ReportActions({
  markdown,
  json,
  basename = "xyainjex-report",
}: {
  markdown: string;
  json: unknown;
  basename?: string;
}) {
  return (
    <div className="report-actions">
      <button
        className="copy"
        onClick={() => downloadText(`${basename}.md`, markdown, "text/markdown")}
      >
        Export MD
      </button>
      <button className="copy" onClick={() => downloadJson(`${basename}.json`, json)}>
        Export JSON
      </button>
    </div>
  );
}
