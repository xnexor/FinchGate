import { useLanguage } from "@/lib/i18n";
import { openUrl } from "@tauri-apps/plugin-opener";
import appIcon from "../../src-tauri/icons/128x128.png";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";

const githubRepositoryUrl = "https://github.com/Aenvo/MuseLink";
const changelogUrls = {
  "zh-CN": "https://github.com/Aenvo/MuseLink/blob/main/CHANGELOG.md",
  en: "https://github.com/Aenvo/MuseLink/blob/main/CHANGELOG.en.md",
} as const;

export default function About({ version, onError }: { version: string; onError: (message: string) => void }) {
  const { language, t } = useLanguage();
  const openChangelog = async () => {
    try {
      await openUrl(changelogUrls[language]);
    } catch {
      onError(t("无法打开更新日志，请稍后重试。"));
    }
  };
  const openRepository = async () => {
    try {
      await openUrl(githubRepositoryUrl);
    } catch {
      onError(t("无法打开 GitHub 仓库，请稍后重试。"));
    }
  };

  return <Card className="gap-0 overflow-hidden py-0 max-[600px]:py-0" aria-labelledby="about-title">
    <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-x-6 gap-y-3 py-5">
      <div className="flex min-w-0 items-center gap-3">
        <img src={appIcon} alt="" width={48} height={48} className="size-12 shrink-0" />
        <div className="min-w-0">
          <CardTitle id="about-title">{t("Muse连接器")}</CardTitle>
          <CardDescription>{t("版本 v{0}", version)}</CardDescription>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" size="sm" onClick={() => void openChangelog()}>
          {t("更新日志")}
        </Button>
        <Button variant="outline" size="sm" onClick={() => void openRepository()}>
          {t("前往 GitHub")}
        </Button>
      </div>
    </CardHeader>
    <Separator />
    <CardFooter className="bg-muted/35 py-4">
      <p>{t("如果 Muse连接器帮到了你，欢迎在 GitHub 点个 Star :)")}</p>
    </CardFooter>
  </Card>;
}
