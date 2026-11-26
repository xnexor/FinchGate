import { createContext, useCallback, useContext, useEffect, type ReactNode } from "react";
import { english } from "@/lib/messages";

export type Language = "zh-CN" | "en";
type Message = keyof typeof english;
export type Translate = (message: Message, ...values: (string | number)[]) => string;

const LanguageContext = createContext<Language>("zh-CN");
const diagnosticPatterns = [
  [/^读取连接器状态失败：([\s\S]+)$/, "读取连接器状态失败：{0}"],
  [/^本地 API 正常，隧道不可用：([\s\S]+)$/, "本地 API 正常，隧道不可用：{0}"],
  [/^文件服务无法监听：([\s\S]+)$/, "文件服务无法监听：{0}"],
  [/^文件服务已停止，隧道清理失败：([\s\S]+)$/, "文件服务已停止，隧道清理失败：{0}"],
  [/^端口 (\d+) 被其他进程占用；本应用未取得服务归属$/, "端口 {0} 被其他进程占用；本应用未取得服务归属"],
] as const satisfies readonly (readonly [RegExp, Message])[];

export function LanguageProvider({ language, children }: { language: Language; children: ReactNode }) {
  useEffect(() => {
    document.documentElement.lang = language;
    document.title = language === "en" ? english["Muse连接器"] : "Muse连接器";
  }, [language]);

  return <LanguageContext.Provider value={language}>{children}</LanguageContext.Provider>;
}

export function useLanguage() {
  const language = useContext(LanguageContext);
  const t = useCallback<Translate>((message, ...values) => {
    const pattern = language === "en" ? english[message] : message;
    return values.length ? pattern.replace(/\{(\d+)\}/g, (placeholder, index) => String(values[Number(index)] ?? placeholder)) : pattern;
  }, [language]);

  const diagnostic = useCallback(function formatDiagnostic(message: string): string {
    if (language === "zh-CN") return message;
    if (Object.prototype.hasOwnProperty.call(english, message)) return t(message as Message);
    for (const [pattern, key] of diagnosticPatterns) {
      const match = pattern.exec(message);
      if (match) return t(key, formatDiagnostic(match[1]));
    }
    return message;
  }, [language, t]);

  return { language, t, diagnostic };
}
