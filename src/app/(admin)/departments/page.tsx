import { getTranslations } from "next-intl/server";

export default async function DepartmentsPage() {
  const t = await getTranslations("Admin");

  return (
    <div className="flex flex-col gap-4 p-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">{t("departments")}</h1>
        <p className="text-sm text-muted-foreground">{t("pageDesc")}</p>
      </div>
      <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
        Departments management — coming in a later slice.
      </div>
    </div>
  );
}
