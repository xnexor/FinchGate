import type { FileAccessMode, FileAccessPolicy, FolderGrant } from "@/lib/use-bridge";
import type { Language, Translate } from "@/lib/i18n";

export const accessOperations = ["search", "read", "write"] as const;

export function folderGrantEnabled(policy: FileAccessPolicy, operation: keyof FolderGrant, alias: string) {
  return policy.folder_grants?.[alias]?.[operation] ?? true;
}

export function editFileAccessPolicy(
  saved: FileAccessPolicy | null,
  mode: FileAccessMode,
  roots: FileAccessPolicy["roots"],
  disks: string[] | null,
): FileAccessPolicy {
  const scope = mode === "full" ? "all_local" : "folders";
  const savedAliases = Object.keys(saved?.roots ?? {});
  const hasRestrictedFolders = (operation: keyof FolderGrant) => !!saved
    && saved[operation] === "folders"
    && savedAliases.some(alias => !folderGrantEnabled(saved, operation, alias));
  const operationScope = (operation: keyof FolderGrant) => {
    if (!saved) return scope;
    if (saved.mode === mode || saved[operation] === "off") return saved[operation];
    return mode === "full" && hasRestrictedFolders(operation) ? "folders" : scope;
  };
  const search = operationScope("search");
  const read = operationScope("read");
  const write = operationScope("write");
  const scopes = [search, read, write];
  const policy: FileAccessPolicy = {
    mode,
    roots: mode === "folders" || scopes.includes("folders") ? roots : saved?.mode === mode ? saved.roots : {},
    disks: scopes.includes("all_local") ? disks ?? undefined : undefined,
    search,
    read,
    write,
  };
  if (saved?.folder_grants && (saved.mode === mode || scopes.includes("folders"))) {
    const pathKey = (path: string) => path.replace(/\//g, "\\").replace(/\\+$/, "").toLowerCase();
    const aliasByPath = new Map(savedAliases.map(alias => [pathKey(saved.roots[alias]), alias]));
    const grantsForRoot = (alias: string | undefined, operation: keyof FolderGrant) => {
      if (alias !== undefined && (saved.mode === mode || saved[operation] === "folders")) {
        return folderGrantEnabled(saved, operation, alias);
      }
      if (saved[operation] !== "folders") return true;
      // New folders follow the operation's current policy.
      return savedAliases.some(previous => folderGrantEnabled(saved, operation, previous));
    };
    policy.folder_grants = Object.fromEntries(Object.entries(policy.roots).map(([alias, path]) => {
      const previous = saved.roots[alias] === path ? alias : aliasByPath.get(pathKey(path));
      return [alias, {
        search: grantsForRoot(previous, "search"),
        read: grantsForRoot(previous, "read"),
        write: grantsForRoot(previous, "write"),
      }];
    }));
  }
  return policy;
}

export function hasFileGrant(policy: FileAccessPolicy | null) {
  return !!policy && accessOperations.some(operation => policy[operation] === "all_local"
    || (policy[operation] === "folders" && Object.keys(policy.roots).some(alias => folderGrantEnabled(policy, operation, alias))));
}

export function accessPolicyKey(policy: FileAccessPolicy) {
  // Snapshot events and IPC replies can serialize object fields in different orders.
  const roots = Object.keys(policy.roots).sort().map(alias => [alias, policy.roots[alias]]);
  const grants = policy.folder_grants;
  const folderGrants = grants ? Object.keys(grants).sort().map(alias => {
    const { search, read, write } = grants[alias];
    return [alias, search, read, write];
  }) : null;
  const fields = [policy.mode, policy.search, policy.read, policy.write, roots, folderGrants];
  return JSON.stringify(policy.disks ? [...fields, [...policy.disks].sort()] : fields);
}

export const agentCredentialIssue = (t: Translate) => ({
  title: t("生成 Muse 专用令牌？"),
  description: t("连接开启时，持有此令牌的 Muse 可以按已保存的搜索、读取与写入权限访问本机文件。令牌应填入 Muse 安全卡片。"),
  action: t("生成专用令牌"),
  busy: t("正在生成 Muse 专用令牌"),
  done: t("Muse 专用令牌已生成"),
});

export function agentTrial(t: Translate, policy: FileAccessPolicy | null, preferredAlias?: string | null) {
  const operation = (["read", "search"] as const).find(key => policy?.[key] === "all_local"
    || (policy?.[key] === "folders" && Object.keys(policy.roots).some(alias => folderGrantEnabled(policy, key, alias))));
  const aliases = policy && operation && policy[operation] === "folders"
    ? Object.keys(policy.roots).filter(alias => folderGrantEnabled(policy, operation, alias)).sort()
    : [];
  const alias = preferredAlias && aliases.includes(preferredAlias) ? preferredAlias : aliases[0] ?? "";
  const folder = alias ? t("目录 {0}", JSON.stringify(alias)) : t("已授权的磁盘");

  if (operation === "read") return {
    aliases, alias, operation,
    prepare: alias ? t("请在目录「{0}」准备一份无敏感内容的 hello.txt。", alias) : t("请准备一份已授权、可以安全试读的文件。"),
    instruction: alias
      ? t("在 {0} 读取 hello.txt。若样本尚未准备，请先问我试读文件路径。", folder)
      : t("先问我要试读的文件路径，再在该路径所对应的授权目录内读取文件。"),
    confirm: t("我已在 Muse 读到文件"),
  };
  if (operation === "search") return {
    aliases, alias, operation,
    prepare: alias ? t("请选一个目录「{0}」里已知的文件名。", alias) : t("请选一个已授权磁盘里已知的文件名。"),
    instruction: t("先问我要找的文件名，再在{0}中搜索，返回实际匹配的路径。若索引仍在建立，请等候并重试。", folder),
    confirm: t("我已在 Muse 找到文件"),
  };
  return {
    aliases, alias, operation,
    prepare: t("你可以在 Muse 核对已授权的目录和权限。"),
    instruction: t("调用 GET /agent/v1/roots，告诉我各操作已授权的目录。确认授权即可，无需创建文件。"),
    confirm: t("我已在 Muse 核对授权"),
  };
}

export function deviceRenameBrief(language: Language, origin: string, deviceName: string, id: string) {
  const endpoint = `${origin}/agent/v1/device-name/confirm`;
  const body = JSON.stringify({ update_id: id });
  if (language === "en") return `Find my existing Custom Connector for ${origin}. Rename it to “Muse Local Files - ${deviceName}” and use “${deviceName}” as the device name in its instructions. Keep its existing endpoint, tools, and credentials. If you cannot identify or update that connector, stop and tell me.
After the change succeeds, use this connector's existing dedicated credential to send POST ${endpoint} with Content-Type: application/json and body ${body}. If the confirmation fails, report the HTTP status and error.`;
  return `请找到 HTTPS 地址为 ${origin} 的现有 Custom Connector，把显示名称更新为「Muse 本机文件 - ${deviceName}」，并把连接器指令中的设备名称更新为「${deviceName}」。沿用原有地址、工具和专用凭证。如果无法确定连接器或无法修改，请停下来告诉我。
改名成功后，请使用该连接器已有的专用凭证发送 POST ${endpoint}，Content-Type 为 application/json，请求体为 ${body}。回执失败时，请告诉我实际 HTTP 状态码和错误。`;
}

export function connectorBrief(language: Language, origin: string, trialInstruction: string, deviceName: string, execEnabled = false) {
  if (language === "en") {
    const introduction = deviceName
      ? `Set up a Custom Connector for the device “${deviceName}”, named “Muse Local Files - ${deviceName}”. Its HTTPS base URL is ${origin} and its API prefix is /agent/v1.
Confirm the device name with me before creating or renaming the connector. If a connector already uses this URL, update its display name. If the requested name exists for a different URL, ask me to choose a distinct name before proceeding.
This connector serves only “${deviceName}”. Ask me which device to use if I haven't specified one or the name is ambiguous. If I name this device, use only this connector. If it is unavailable, report that and don't switch to a different device. Use this connector for the setup test below.`
      : `Set up a Custom Connector named “Muse Local Files”. Its HTTPS base URL is ${origin} and its API prefix is /agent/v1.`;
    const execSection = execEnabled ? `
- POST /agent/v1/exec runs a command inside an authorized project subfolder (never a bare drive root). Prefer {"root":"alias","cwd":"relative project folder","mode":"direct","program":"git","args":["status"],"reason":"brief intent"}. For shell pipelines or scripts, set mode to "powershell" or "cmd" and pass "command" instead of program/args. Commands run inside a Windows write-restricted sandbox by default. Fast auto-allowed commands return HTTP 200 directly; long-running or approval-required jobs return HTTP 202 with job_id, status ("running" or "awaiting_approval"), and retry_after_ms. When status is "awaiting_approval" or "running", do NOT stop and wait for me to reply in chat—the approval dialog pops up automatically on Windows (120s timeout). Immediately keep polling GET /agent/v1/exec/<job_id>?wait_ms=20000 until status reaches a terminal state ("completed", "failed", "timed_out", "cancelled", "denied", or "expired"). The endpoint returns immediately once I approve/deny or the job finishes. If status becomes "expired" or "denied", report it clearly instead of retrying automatically. Cap polling at 8 consecutive calls for "awaiting_approval" and 18 consecutive calls for "running"; if still unfinished, report the job_id and current status and ask whether to cancel via POST /agent/v1/exec/<job_id>/cancel.` : "";
    return `${introduction}
Use a security card to collect the dedicated agent-token. Send Authorization: Bearer <token> on each request. Store it separately and use it only for requests to ${origin}/agent/v1/. Show only the results in the conversation.

The API returns JSON. Send Content-Type: application/json for POST requests and URL-encode GET query parameters. Use the authorized alias as root and the relative path within it as path.
- GET /agent/v1/roots returns roots.search, roots.read, and roots.write, each listing the aliases authorized for that operation.
- GET /agent/v1/locations/desktop returns root, path, and the absolute_path of the Windows Desktop. Use this to locate the Desktop if it is within the authorized scope.
- POST /agent/v1/search accepts {"name":"part of the file name","limit":30}. Optional fields: root, extensions, modified_since_ms, modified_before_ms, and cursor. If you know the drive letter, pass its root alias first. Results include hits, complete, scanning, backend, scopes, and optional next_cursor and retry_after_ms. Each hit has root, path, kind, size, and modified_ms. When scanning is true, show the current results and scopes still being indexed, wait for retry_after_ms, and try again. If indexing is unfinished or complete is false, say that coverage is incomplete. To paginate, pass next_cursor as cursor and keep the other query parameters the same.
- If search returns HTTP 409 with search_index_cleared, ask the user to open Settings → Data in MuseLink and select Rebuild index. Wait for the user before searching again.
- GET /agent/v1/list?root=<alias>&path=<relative-folder> lists a folder. Use an empty path to list the root.
- GET /agent/v1/read?root=<alias>&path=<relative-file> returns encoding and content. The encoding is text or base64.
- POST /agent/v1/write accepts {"root":"alias","path":"relative file","content":"file content","encoding":"text"}. Encoding may also be base64. Write files only at my explicit request.
- POST /agent/v1/mkdir accepts {"root":"alias","path":"relative folder"}. Create folders only at my explicit request.${execSection}

Verify the connector once setup is complete. ${trialInstruction} If a request fails, report the endpoint, HTTP status, and actual error.`;
  }

  const introduction = deviceName
    ? `请为设备「${deviceName}」配置名为「Muse 本机文件 - ${deviceName}」的 Custom Connector。HTTPS 地址为 ${origin}，接口前缀为 /agent/v1。
创建或改名前请向我确认设备名称。若此地址已有连接器，请更新它的显示名称。若同名连接器指向其他地址，请先让我选择一个不同的名称。
此连接器只对应设备「${deviceName}」。若我没有指定设备，或名称有歧义，请先问我要用哪台。点名这台设备时，只使用此连接器。若设备不可用，请报告情况，不要自动换到其他设备。下方的接入试用请使用此连接器。`
    : `请配置一个名为「Muse 本机文件」的 Custom Connector。HTTPS 地址为 ${origin}，接口前缀为 /agent/v1。`;
  const execSection = execEnabled ? `
- POST /agent/v1/exec 在已授权的具体项目子目录内执行命令（不可直接传盘符根目录）。优先使用直调模式：{"root":"目录别名","cwd":"项目相对路径","mode":"direct","program":"git","args":["status"],"reason":"简要意图"}；需要管道或脚本时把 mode 设为 "powershell" 或 "cmd" 并传 "command"。命令默认运行在 Windows 写受限沙箱中。快速且免审批的命令会直接返回 HTTP 200 与完整输出；耗时或需人工审批的任务返回 HTTP 202（含 job_id、status 为 "running" 或 "awaiting_approval"、retry_after_ms）。若状态为 "awaiting_approval" 或 "running"，不要中断当前工作流或停下来等我在聊天里回复——电脑端会自动置顶弹出审批窗（120 秒有效），请直接持续轮询 GET /agent/v1/exec/<job_id>?wait_ms=20000 直到进入终态（"completed"、"failed"、"timed_out"、"cancelled"、"denied"、"expired"）；我一旦在电脑上点允许/拒绝或任务结束，该接口会立刻返回，无需我回聊天报备。若状态变为 "expired"（审批超时）或 "denied"（已拒绝），请直接告知我，不要自动重试。轮询请设上限："awaiting_approval" 最多连续 8 次，"running" 最多连续 18 次；达到上限仍未结束时，汇报 job_id 与当前状态，并询问是否通过 POST /agent/v1/exec/<job_id>/cancel 中止。` : "";
  return `${introduction}
请用安全卡片收集此连接专用的 agent-token，每次请求发送 Authorization: Bearer <令牌>。使用独立的凭证项，只在请求 ${origin}/agent/v1/ 下的接口时使用。对话中只显示调用结果。

接口返回 JSON。POST 请求发送 Content-Type: application/json。GET 查询参数需做 URL 编码。各路径使用授权别名 root 与该别名内的相对路径 path。
- GET /agent/v1/roots 返回 roots.search、roots.read、roots.write，各自列出对应操作的目录别名。
- GET /agent/v1/locations/desktop 返回 root、path 和 Windows 实际桌面的 absolute_path。需要定位桌面时使用，桌面须在授权范围内。
- POST /agent/v1/search 接收 {"name":"文件名的一部分","limit":30}。可选 root、extensions、modified_since_ms、modified_before_ms 和 cursor。知道盘符时优先传对应的 root。返回 hits、complete、scanning、backend、scopes 及可选 next_cursor、retry_after_ms。命中含 root、path、kind、size、modified_ms。若 scanning 为 true，按 retry_after_ms 等待后再查，先告知当前有哪些结果及未完成的范围。扫描未结束或 complete 为 false 时，标明覆盖还不完整。分页时把 next_cursor 作为下一次的 cursor，其余查询参数保持一致。
- 若搜索返回 HTTP 409 且 error 为 search_index_cleared，告诉用户在桌面连接器的「设置 → 数据」中点「重新建立索引」。等待用户操作后再搜索。
- GET /agent/v1/list?root=<目录别名>&path=<相对目录> 列出目录。列根目录时 path 填空字符串。
- GET /agent/v1/read?root=<目录别名>&path=<相对文件> 返回 encoding 和 content，encoding 为 text 或 base64。
- POST /agent/v1/write 接收 {"root":"目录别名","path":"相对文件","content":"文件内容","encoding":"text"}，encoding 也可以为 base64。写入仅按我的明确请求执行。
- POST /agent/v1/mkdir 接收 {"root":"目录别名","path":"相对目录"}，仅按我的明确请求建目录。${execSection}

接入后请验证一次。${trialInstruction} 若调用失败，请报告实际接口、HTTP 状态码和错误。`;
}
