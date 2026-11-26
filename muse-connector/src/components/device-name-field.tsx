import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useLanguage } from "@/lib/i18n";
import type { DeviceNameModel } from "@/lib/use-device-name";

export default function DeviceNameField({
  id,
  deviceName,
  layout = "stacked",
}: {
  id: string;
  deviceName: DeviceNameModel;
  layout?: "stacked" | "inline";
}) {
  const { t } = useLanguage();
  const { value, dirty, disabled, canSave, invalid, error, update, save } = deviceName;

  if (layout === "inline") {
    return (
      <form noValidate className="flex flex-col gap-3" onSubmit={event => { event.preventDefault(); void save(); }}>
        <Field className="gap-3" data-invalid={invalid}>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
            <div className="flex min-w-0 flex-col gap-1">
              <FieldLabel htmlFor={id}>{t("设备名称")}</FieldLabel>
              <FieldDescription id={`${id}-help`}>{t("用来区分不同的电脑，更新后需重新发给 Muse")}</FieldDescription>
            </div>
            <Input
              id={id}
              name="device_name"
              className="w-full sm:w-64 shrink-0"
              value={value}
              required
              disabled={disabled}
              placeholder={t("例如：笔记本、台式机、客厅电脑")}
              autoComplete="off"
              spellCheck={false}
              aria-invalid={invalid}
              aria-describedby={invalid ? `${id}-help ${id}-error` : `${id}-help`}
              onChange={event => update(event.target.value)}
            />
          </div>
          {invalid ? <FieldError id={`${id}-error`}>{t("请输入 1–32 个字符，可用文字、0–9、空格、连字符和下划线，首尾不能有空格。")}</FieldError> : null}
          {error ? <FieldError>{error}</FieldError> : null}
          {dirty ? (
            <div className="flex flex-wrap items-center justify-end gap-2">
              <Button type="button" size="sm" variant="ghost" disabled={disabled} onClick={() => update(null)}>{t("取消")}</Button>
              <Button type="submit" size="sm" disabled={!canSave}>{t("保存名称")}</Button>
            </div>
          ) : null}
        </Field>
      </form>
    );
  }

  return (
    <form noValidate onSubmit={event => { event.preventDefault(); void save(); }}>
      <Field className="gap-2" data-invalid={invalid}>
        <FieldLabel htmlFor={id}>{t("设备名称")}</FieldLabel>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            id={id}
            name="device_name"
            className="min-w-28 flex-1"
            value={value}
            required
            disabled={disabled}
            placeholder={t("例如：笔记本、台式机、客厅电脑")}
            autoComplete="off"
            spellCheck={false}
            aria-invalid={invalid}
            aria-describedby={invalid ? `${id}-help ${id}-error` : `${id}-help`}
            onChange={event => update(event.target.value)}
          />
          <Button type="submit" size="sm" disabled={!canSave}>{t("保存名称")}</Button>
          {dirty ? <Button type="button" size="sm" variant="ghost" disabled={disabled} onClick={() => update(null)}>{t("取消")}</Button> : null}
        </div>
        <FieldDescription id={`${id}-help`}>{t("用来区分不同的电脑，更新后需重新发给 Muse")}</FieldDescription>
        {invalid ? <FieldError id={`${id}-error`}>{t("请输入 1–32 个字符，可用文字、0–9、空格、连字符和下划线，首尾不能有空格。")}</FieldError> : null}
        {error ? <FieldError>{error}</FieldError> : null}
      </Field>
    </form>
  );
}
